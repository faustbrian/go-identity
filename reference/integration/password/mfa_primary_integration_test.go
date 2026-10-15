//go:build integration

package passwordintegration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
)

// This registered MFA invocation is a deliberate adapter seam: proof issuance,
// signature validation, primary fences, proof consumption, kernel, audit and
// lifecycle are real. Its tiny protected effect is NOT a production enrollment.
type mfaPrimaryFixturePhase struct {
	admission  passworddb.MFAEnableAdmission
	command    identity.Command
	rollback   bool
	checkpoint string
	enrollment mfapg.PreparedTOTPEnrollment
}

func (*mfaPrimaryFixturePhase) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}
}
func (p *mfaPrimaryFixturePhase) FeatureOperations() []identity.FeatureOperation {
	spec, _ := p.command.Feature()
	return []identity.FeatureOperation{spec.Operation}
}
func (p *mfaPrimaryFixturePhase) ValidateFeatureCommand(c identity.Command, plan kernel.CommandPlan) error {
	if c != p.command || plan.Feature == nil || plan.Feature.Contributor != p.Descriptor() || plan.Lifecycle == nil || plan.Lifecycle.EventType != "factor.enrollment-created.v1" {
		return identity.ForbiddenError{}
	}
	return nil
}
func (p *mfaPrimaryFixturePhase) ApplyFeature(ctx context.Context, w kernel.Work, c identity.Command) (identity.FeatureReceipt, error) {
	p.checkpoint = "consume"
	if err := p.admission.Admit(ctx, w, p, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.enrollment.Persist(ctx, w, p, c, p.admission); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := c.Feature()
	p.checkpoint = "effect"
	if _, err := w.Exec(ctx, `INSERT INTO public.mfa_primary_test_effects(command_id,factor_id) VALUES($1,$2)`, string(spec.Binding.CommandID), spec.Binding.RecordID); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if p.rollback {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	return identity.FeatureReceipt{Operation: spec.Operation, BeforeVersion: 0, AfterVersion: 1}, nil
}
func (p *mfaPrimaryFixturePhase) CheckFeatureCommit(ctx context.Context, w kernel.Work, c identity.Command) error {
	p.checkpoint = "final-check"
	return p.admission.Check(ctx, w, p, c)
}
func (p *mfaPrimaryFixturePhase) RecoverParticipant(ctx context.Context, w kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	primary, err := p.admission.Recover(ctx, w, p)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	factor, err := p.enrollment.Recover(ctx, w, p)
	if err != nil || factor != primary {
		return kernel.RecoveryUnknown, err
	}
	return factor, nil
}

func testNativeMFAEnablePrimary(t *testing.T, ctx context.Context, pool *database.Pool, config passworddb.ReauthenticationConfig, source *passworddb.ReauthenticationService, verification passworddb.ReauthenticationRequest, expected session.Session, otpConfirmation string) {
	t.Helper()
	// Explicit pre-existing-session fixture seam: install synchronizer state
	// using the session owner's digest representation. This is not issuance
	// evidence; later reference coverage must obtain it through public issuance.
	binding, err := expected.Bindings()
	if err != nil {
		t.Fatal("fixture source session unavailable")
	}
	csrf, _ := session.NewCSRFToken()
	csrfKey, _ := session.NewCSRFKey(7, bytes.Repeat([]byte{91}, 32))
	csrfState, err := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: binding.TenantID, SessionID: binding.SessionID, SessionVersion: binding.Version})
	if err != nil {
		t.Fatal("fixture synchronizer generation failed")
	}
	csrfSpec, _ := csrfState.Bindings()
	csrfWire, _ := json.Marshal(csrfSpec)
	if _, err := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET record=jsonb_set(jsonb_set(record,'{Schema}',to_jsonb((record->>'Schema')::integer + CASE WHEN record ? 'CSRF' THEN 0 ELSE 1 END)),'{CSRF}',$2::jsonb) WHERE session_id=$1`, binding.SessionID, csrfWire); err != nil {
		t.Fatal("fixture synchronizer installation failed")
	}
	expected, err = session.NewSessionWithCSRF(binding, csrfState)
	if err != nil {
		t.Fatal("fixture original session rejected synchronizer")
	}
	history, err := (mfapg.TOTPFactorMigrationSource{Base: mfapg.ContinuationMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2}, Version: 3}).Load(ctx)
	if err != nil {
		t.Fatal("owned MFA history rejected")
	}
	for _, item := range history {
		if _, err = pool.Raw().Exec(ctx, item.UpSQL()); err != nil {
			t.Fatal("owned MFA installation failed")
		}
	}
	// This pre-existing-account reconciliation is an explicit fixture seam;
	// missing factor state must not be inferred from its single-factor session.
	seedID, _ := identity.NewCommandID()
	seedWire, _ := base64.RawURLEncoding.Strict().DecodeString(string(seedID))
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.identity_command_id_claims(command_id,tenant_id,purpose,fingerprint,fingerprint_key_version,safe_fields) VALUES($1,$2,'identity.password.signup',$3,1,decode('01','hex'))`, seedWire, string(verification.TenantID), make([]byte, 32)); err != nil {
		t.Fatal("factor reconciliation fixture claim rejected")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.commands(command_id,tenant_id,purpose) VALUES($1,$2,'identity.password.signup')`, seedWire, string(verification.TenantID)); err != nil {
		t.Fatal("factor reconciliation fixture command rejected")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES($1,$2,1,0,$3,'identity.password.signup')`, string(verification.TenantID), string(verification.Caller.Request.Subject.ID), seedWire); err != nil {
		t.Fatal("known-empty factor reconciliation rejected")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	defer clear(key)
	keys, err := keyring.New(map[string][]byte{"totp-v1": key})
	if err != nil {
		t.Fatal("fixture local key rejected")
	}
	preparer, err := mfapg.NewTOTPEnrollmentPreparer(keys, "totp-v1")
	if err != nil {
		t.Fatal("native pending preparer rejected")
	}
	if _, err := pool.Raw().Exec(ctx, `CREATE TABLE public.mfa_primary_test_effects(command_id text PRIMARY KEY,factor_id text NOT NULL)`); err != nil {
		t.Fatal("protected fixture effect unavailable")
	}
	primary, err := passworddb.NewMFAEnablePrimarySource(source, passworddb.MFAEnablePrimaryConfig{Audience: "backend", MaximumAge: 5 * time.Minute, PrimaryFreshFor: 5 * time.Minute})
	if err != nil {
		t.Fatal("native enrollment primary composition failed")
	}
	verification.Target = passworddb.ReauthenticationTarget{Purpose: "identity.password.verify", Action: "identity.mfa.enable", Audience: "backend"}
	issued, err := source.Verify(ctx, verification)
	if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("live MFA-targeted password verification failed")
	}
	newRequest := func() passworddb.MFAEnablePrimaryRequest {
		id, _ := identity.NewCommandID()
		factor, _ := identity.NewCommandID()
		return passworddb.MFAEnablePrimaryRequest{TenantID: verification.TenantID, CommandID: id, FactorID: string(factor), Session: verification.Session, Proof: issued.Proof, Caller: verification.Caller}
	}
	r := newRequest()
	admitted, err := primary.Prepare(ctx, r)
	if err != nil {
		t.Fatal("original primary admission rejected")
	}
	snapshot, err := admitted.Snapshot()
	if err != nil {
		t.Fatal("native original custody export rejected")
	}
	defer clear(snapshot)
	restored, err := primary.Restore(ctx, r, snapshot)
	if err != nil {
		t.Fatal("native original custody restore rejected")
	}
	original, err := restored.Original()
	want, wantErr := expected.Bindings()
	got, gotErr := original.Bindings()
	again, againErr := restored.Snapshot()
	defer clear(again)
	if err != nil || wantErr != nil || gotErr != nil || againErr != nil || got.Authentication.Proof != want.Authentication.Proof || got.SessionID != want.SessionID || !bytes.Equal(snapshot, again) {
		t.Fatal("restoration changed original evidence or timestamps")
	}
	keyed, _ := identity.NewIdempotencyKey([]byte("public-enrollment-input"))
	caller := r.Caller.Clone()
	caller.PolicyRevision = authorization.Revision(config.Coordinator.QueryPolicy.PolicyVersion)
	caller.Request.Tenant = authorization.TenantID(r.TenantID)
	caller.Request.Action = "identity.mfa.enable"
	caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(want.UserID)}
	public := mfa.EnableRequest{TenantID: r.TenantID, FactorPolicy: mfa.FactorPolicy{Method: "totp", RecoveryCodes: 10}, PrimaryProof: want.Authentication.Proof, Reauthentication: r.Proof, Session: r.Session, IdempotencyKey: keyed, Caller: caller, Network: "127.0.0.1"}
	port, err := primary.PrepareEnrollment(ctx, public, r.CommandID, mfa.FactorID(r.FactorID))
	if err != nil {
		t.Fatal("public original-primary enrollment source rejected")
	}
	portWire, err := port.Snapshot()
	defer clear(portWire)
	if err != nil || !bytes.Equal(snapshot, portWire) {
		t.Fatal("public enrollment source replaced original custody")
	}
	if _, err := primary.RestoreEnrollment(ctx, public, r.CommandID, mfa.FactorID(r.FactorID), snapshot); err != nil {
		t.Fatal("public source port could not restore original preparation")
	}
	t.Run("uri-original-session-restoration", func(t *testing.T) {
		testURIPrimaryRestoration(t, ctx, primary, r, snapshot, csrf, csrfKey, caller)
	})
	wrongPrimary := public
	wrongPrimary.PrimaryProof.ID = "AAAAAAAAAAAAAAAAAAAABA"
	if _, err := primary.PrepareEnrollment(ctx, wrongPrimary, r.CommandID, mfa.FactorID(r.FactorID)); err == nil {
		t.Fatal("unbound client-selected primary proof admitted")
	}
	if _, err := primary.RestoreEnrollment(ctx, wrongPrimary, r.CommandID, mfa.FactorID(r.FactorID), snapshot); err == nil {
		t.Fatal("restore substituted another primary identity")
	}
	for _, change := range []func(*passworddb.MFAEnablePrimaryRequest){
		func(r *passworddb.MFAEnablePrimaryRequest) {
			r.Session = auth.NewBearerCredential("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		},
		func(r *passworddb.MFAEnablePrimaryRequest) { r.TenantID = "foreign" },
		func(r *passworddb.MFAEnablePrimaryRequest) { r.Proof.Action = "identity.password.change" },
		func(r *passworddb.MFAEnablePrimaryRequest) { r.Proof.SessionVersion++ },
	} {
		wrong := r
		change(&wrong)
		if _, err := primary.Restore(ctx, wrong, snapshot); err == nil {
			t.Fatal("substituted original bearer/proof restoration accepted")
		}
	}
	for _, wrong := range [][]byte{nil, []byte(`{}`), append(bytes.Clone(snapshot), '\n'), bytes.Replace(snapshot, []byte(`"Schema":1`), []byte(`"Schema":2`), 1)} {
		if _, err := primary.Restore(ctx, r, wrong); err == nil {
			t.Fatal("noncanonical or unsupported original custody accepted")
		}
	}
	stale, err := passworddb.NewMFAEnablePrimarySource(source, passworddb.MFAEnablePrimaryConfig{Audience: "backend", MaximumAge: 5 * time.Minute, PrimaryFreshFor: time.Second})
	if err != nil {
		t.Fatal("bounded primary freshness configuration rejected")
	}
	if _, err = stale.Prepare(ctx, r); err == nil {
		t.Fatal("recent activity renewed original authentication freshness")
	}
	foreign := r
	foreign.TenantID = "AAAAAAAAAAAAAAAAAAAABA"
	if _, err = primary.Prepare(ctx, foreign); err == nil {
		t.Fatal("cross-tenant bearer/proof admission accepted")
	}
	wrong := r
	wrong.Proof.Action = "identity.password.change"
	if _, err = primary.Prepare(ctx, wrong); err == nil {
		t.Fatal("changed signed action admitted")
	}
	executionPool := pool
	prepare := func(request passworddb.MFAEnablePrimaryRequest, rollback bool) (*kernel.Coordinator, *mfaPrimaryFixturePhase, identity.CommandBinding, kernel.CommandPlan) {
		t.Helper()
		admission, err := primary.Prepare(ctx, request)
		if err != nil {
			t.Fatal("signed original primary rejected")
		}
		op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.enable", SchemaID: "mfa-enable", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		b := identity.CommandBinding{CommandID: request.CommandID, TenantID: request.TenantID, UserID: identity.UserID(request.Caller.Request.Subject.ID), ActorID: identity.ActorID(request.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: op.SchemaVersion, PolicyID: "identity-mfa", PolicyVersion: 9, RecordID: request.FactorID, CorrelationID: string(request.CommandID)}
		var version string
		var at time.Time
		if pool.Raw().QueryRow(ctx, `SELECT version::text,clock_timestamp() FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)).Scan(&version, &at) != nil {
			t.Fatal("authoritative preparation selection failed")
		}
		factorVersion, err := strconv.ParseUint(version, 10, 64)
		if err != nil {
			t.Fatal("factor generation malformed")
		}
		enrollment, err := preparer.Prepare(ctx, mfapg.TOTPEnrollmentPreparation{TenantID: b.TenantID, UserID: b.UserID, FactorID: b.RecordID, AuthorityVersion: factorVersion, CreatedAt: at, TTL: 5 * time.Minute, Profile: mfa.TOTPProfile{Algorithm: "SHA1", Digits: 6, Period: 30 * time.Second, Issuer: "Example"}})
		if err != nil {
			t.Fatal("native pending generation rejected")
		}
		fields, err := enrollment.Fields()
		if err != nil {
			t.Fatal("pending intent fields unavailable")
		}
		c, err := admission.Command(b, fields)
		if err != nil {
			t.Fatal("frozen MFA primary command rejected")
		}
		p := &mfaPrimaryFixturePhase{admission: admission, command: c, rollback: rollback, enrollment: enrollment}
		domain, err := kernel.NewRepository(executionPool, kernel.Config{MaximumDuration: 3 * time.Second})
		if err != nil {
			t.Fatal("native domain unavailable")
		}
		audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
		if err != nil {
			t.Fatal("native audit unavailable")
		}
		lifecycle, err := lifecyclepg.NewContributor()
		if err != nil {
			t.Fatal("native lifecycle unavailable")
		}
		registry, err := kernel.NewContributorRegistry([]kernel.Contributor{domain, audits, lifecycle, p})
		if err != nil {
			t.Fatal("native MFA registration rejected")
		}
		coordinator, err := kernel.NewCoordinator(executionPool, registry, config.Coordinator)
		if err != nil {
			t.Fatal("native MFA coordinator rejected")
		}
		builder, _ := audit.NewBuilder(audit.BuilderConfig{})
		seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC(), Action: b.OperationID, Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "factor", ID: b.RecordID}, Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.type": "factor", "aggregate.id": b.RecordID, "aggregate.before_version": "0", "aggregate.after_version": "1", "retention.class": "protected"}})
		if err != nil {
			t.Fatal("native audit seed rejected")
		}
		digest, err := kernel.FeatureAuditBindingDigest(b, op, "factor", seed)
		if err != nil {
			t.Fatal("native audit scope rejected")
		}
		plan, err := coordinator.PrepareCommandPlan(b, c, kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "factor", Feature: &kernel.FeatureRegistration{Contributor: p.Descriptor(), Operation: op}, Lifecycle: &kernel.LifecyclePlan{EventType: "factor.enrollment-created.v1", BeforeVersion: 0, AfterVersion: 1}, Audits: []kernel.AuditPlan{{EventType: b.OperationID, SchemaVersion: 1, Required: true, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, RetentionPolicyVersion: 1, RetentionClass: "protected", BindingDigest: digest}}})
		if err != nil {
			t.Fatal("native MFA plan rejected")
		}
		return coordinator, p, b, plan
	}
	execute := func(coordinator *kernel.Coordinator, p *mfaPrimaryFixturePhase, b identity.CommandBinding, plan kernel.CommandPlan) (identity.CommandResult, error) {
		reservation, result, err := coordinator.ReserveCommand(ctx, b, p.command, plan)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
			return result, err
		}
		work, err := coordinator.Begin(ctx, reservation)
		if err != nil {
			return identity.CommandResult{}, err
		}
		defer coordinator.Abort(work, identity.UnavailableError{})
		result, err = coordinator.ApplyFeature(ctx, work, p.command)
		if err != nil {
			return coordinator.Abort(work, err)
		}
		return coordinator.Commit(work, result)
	}
	assertEffects := func(consumed bool, count int) {
		t.Helper()
		var used bool
		var effects int
		if pool.Raw().QueryRow(ctx, `SELECT consumed_command_id IS NOT NULL,(SELECT count(*) FROM public.mfa_primary_test_effects) FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(issued.Proof.Proof.ID)).Scan(&used, &effects) != nil || used != consumed || effects != count {
			t.Fatal("proof consumption and protected effect diverged")
		}
		var pending, active int64
		var generation string
		if pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_mfa.totp_factors WHERE state=1 AND confirmed_at IS NULL AND NOT reveal_consumed),active_factors,version::text FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(verification.TenantID), string(verification.Caller.Request.Subject.ID)).Scan(&pending, &active, &generation) != nil || pending != int64(count) || active != 0 || generation != strconv.Itoa(count+1) {
			t.Fatal("pending creation/authority generation diverged or activated without code")
		}
	}
	coordinator, p, b, plan := prepare(r, true)
	result, err := execute(coordinator, p, b, plan)
	if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("protected failure did not roll back")
	}
	assertEffects(false, 0)
	for _, scenario := range []string{"missing-factor-authority", "stale-factor-generation", "already-enrolled"} {
		r = newRequest()
		coordinator, p, b, plan = prepare(r, false)
		switch scenario {
		case "missing-factor-authority":
			_, err = pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID))
		case "stale-factor-generation":
			_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID))
		case "already-enrolled":
			_, err = pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET active_factors=1 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID))
		}
		if err != nil {
			t.Fatal("factor authority denial fixture failed")
		}
		result, err = execute(coordinator, p, b, plan)
		if scenario == "missing-factor-authority" {
			if _, e := pool.Raw().Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose) VALUES($1,$2,1,0,$3,'identity.password.signup')`, string(b.TenantID), string(b.UserID), seedWire); e != nil {
				t.Fatal("factor reconciliation fixture restore failed")
			}
		} else {
			if _, e := pool.Raw().Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=1,active_factors=0 WHERE tenant_id=$1 AND user_id=$2`, string(b.TenantID), string(b.UserID)); e != nil {
				t.Fatal("factor denial fixture restore failed")
			}
		}
		if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
			t.Fatal("unknown/stale/enrolled authority admitted password-only enrollment")
		}
		assertEffects(false, 0)
	}
	r = newRequest()
	coordinator, p, b, plan = prepare(r, false)
	if _, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended' WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(b.UserID)); err != nil {
		t.Fatal("current blocking fixture failed")
	}
	result, err = execute(coordinator, p, b, plan)
	if _, restoreErr := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id=$1 AND user_id=$2`, string(r.TenantID), string(b.UserID)); restoreErr != nil {
		t.Fatal("blocking fixture cleanup failed")
	}
	if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("blocking between prepare and mutation admitted")
	}
	assertEffects(false, 0)
	r = newRequest()
	coordinator, p, b, plan = prepare(r, false)
	result, err = execute(coordinator, p, b, plan)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted {
		t.Fatalf("native atomic enrollment-primary use failed: error type %T, outcome %d, boundary %s", err, result.Outcome, p.checkpoint)
	}
	assertEffects(true, 1)
	wire, _ := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	var same bool
	if pool.Raw().QueryRow(ctx, `SELECT consumed_command_id=$2 AND consumed_purpose='identity.mfa.enable' FROM identity_password.reauthentication_records WHERE proof_id=$1`, string(issued.Proof.Proof.ID), wire).Scan(&same) != nil || !same {
		t.Fatal("consumer marker lost original command/action")
	}
	r = newRequest()
	coordinator, p, b, plan = prepare(r, false)
	result, err = execute(coordinator, p, b, plan)
	if err == nil || result.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("second command reused consumed primary proof")
	}
	assertEffects(true, 1)
	// Reuse the native protocol fault boundary to prove both sides of an
	// ambiguous commit. No new proof or effect is generated during recovery.
	ordinaryConfig, ordinaryPrimary, ordinaryPool := config, primary, executionPool
	for _, before := range []bool{true, false} {
		issued, err = source.Verify(ctx, verification)
		if err != nil || issued.Outcome != identity.CommitOutcomeCommitted {
			t.Fatal("fresh ambiguity proof unavailable")
		}
		fault := &reauthenticationCommitFault{before: before, marker: []byte("UPDATE identity_password.reauthentication_records SET consumed_command_id")}
		faultPool, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
		if err != nil {
			t.Fatal("isolated protocol-fault pool unavailable")
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if faultPool.Close(cleanup) != nil {
				t.Error("protocol-fault pool cleanup failed")
			}
		}()
		config.Coordinator.LeaseDuration = 500 * time.Millisecond
		faultSource, err := passworddb.NewReauthenticationService(faultPool, config)
		if err != nil {
			t.Fatal("fault source rejected")
		}
		primary, err = passworddb.NewMFAEnablePrimarySource(faultSource, passworddb.MFAEnablePrimaryConfig{Audience: "backend", MaximumAge: 5 * time.Minute, PrimaryFreshFor: 5 * time.Minute})
		if err != nil {
			t.Fatal("fault enrollment primary rejected")
		}
		executionPool = faultPool
		r = newRequest()
		coordinator, p, b, plan = prepare(r, false)
		result, err = execute(coordinator, p, b, plan)
		if err == nil || result.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() {
			t.Fatal("ambiguous enrollment-primary commit fabricated a known outcome")
		}
		query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
		caller := verification.Caller.Clone()
		caller.PolicyRevision = authorization.Revision(config.Coordinator.QueryPolicy.PolicyVersion)
		caller.Request.Tenant, caller.Request.Action = authorization.TenantID(b.TenantID), authorization.Action(b.OperationID)
		caller.Request.Resource = authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}
		bounded, stop := context.WithTimeout(ctx, 3*time.Second)
		ticker := time.NewTicker(10 * time.Millisecond)
		for {
			recovered, recoveryErr := coordinator.RecoverFeatureCommand(bounded, query, caller)
			want := identity.CommitOutcomeCommitted
			if before {
				want = identity.CommitOutcomeNotCommitted
			}
			if recovered.Outcome == want {
				if !before && recoveryErr != nil {
					t.Fatal("known committed primary recovery failed")
				}
				break
			}
			select {
			case <-bounded.Done():
				ticker.Stop()
				stop()
				t.Fatalf("original primary ambiguity did not reconcile: before=%t, outcome=%d, error type=%T", before, recovered.Outcome, recoveryErr)
			case <-ticker.C:
			}
		}
		ticker.Stop()
		stop()
		if before {
			assertEffects(false, 1)
		} else {
			assertEffects(true, 2)
		}
	}
	// The short fault lease and injected connection belong only to ambiguity
	// cases. The subsequent public journey must use its ordinary native profile,
	// not inherit a subsecond lease from an already completed fault scenario.
	config, primary, executionPool = ordinaryConfig, ordinaryPrimary, ordinaryPool
	t.Run("public-enrollment", func(t *testing.T) {
		testPublicTOTPEnrollment(t, ctx, pool, config, source, verification, expected, keys, primary, csrf, csrfKey, otpConfirmation)
	})
}
