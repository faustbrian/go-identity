//go:build integration

package mfapostgres

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

// External Google/browser admission and encrypted preparation are bounded
// fixtures, not authentication. The real coordinator owns original command
// custody, reservation, Work, final checks, audit/outbox and rollback. No session
// is issued here. The SQL participant below models only the one-use boundary,
// not production capability storage or cryptographic proof verification.
type oneTapFactorInvocation struct {
	oauthSigninFactorInvocation
	expected kernel.ProviderAccountAdmission
}

func (*oneTapFactorInvocation) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.onetap-completion", Version: 1}
}

func (p *oneTapFactorInvocation) AdmitFeaturePreparation(ctx context.Context, w kernel.Work, command identity.Command) error {
	f, ok := command.Feature()
	b, registration, _, err := w.FeatureScope(p)
	if err != nil || !ok || command != p.original || b != f.Binding || registration.Operation != kernel.OneTapCallbackOperation() {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func (p *oneTapFactorInvocation) ValidateOneTapCallbackConsumption(command identity.Command, plan kernel.CapabilityPlan) error {
	if command != p.original || p.declaration.Capability == nil || plan != *p.declaration.Capability {
		return identity.ForbiddenError{}
	}
	account, err := kernel.OneTapCallbackAccount(command)
	if err != nil || account != p.expected {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *oneTapFactorInvocation) check(ctx context.Context, w kernel.Work, command identity.Command) error {
	account, err := kernel.OneTapCallbackAccount(command)
	if err != nil || account != p.expected || command != p.original {
		return identity.ForbiddenError{}
	}
	state, err := RequireOneTapCallbackFactors(ctx, w, p, command, 1)
	if err == nil && (state.Version() != 1 || state.RequireEmailRecovery("tenant-a", "user-a") != nil) {
		return identity.ForbiddenError{}
	}
	return err
}

func (p *oneTapFactorInvocation) ApplyFeature(ctx context.Context, w kernel.Work, command identity.Command) (identity.FeatureReceipt, error) {
	p.retained, p.command = w, command
	consumed, err := w.OneTapCallbackConsumption(p)
	f, ok := command.Feature()
	if err != nil || !ok || consumed.Command != f.Binding || consumed.Plan != *p.declaration.Capability || consumed.Generation == 0 {
		return identity.FeatureReceipt{}, identity.ForbiddenError{}
	}
	if _, err := w.Exec(ctx, `INSERT INTO oauth_signin_factor_probe VALUES($1)`, string(f.Binding.CommandID)); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := p.check(ctx, w, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	p.applied = true
	if p.mode == "current" {
		other, err := p.pool.Raw().Begin(ctx)
		if err != nil {
			return identity.FeatureReceipt{}, err
		}
		_, lockErr := other.Exec(ctx, `SELECT version FROM identity_mfa.factor_authorities WHERE tenant_id='tenant-a' AND user_id='user-a' FOR UPDATE NOWAIT`)
		_ = other.Rollback(ctx)
		var locked *pgconn.PgError
		p.lockHeld = errors.As(lockErr, &locked) && locked.Code == "55P03"
		if !p.lockHeld {
			return identity.FeatureReceipt{}, identity.ForbiddenError{}
		}
	}
	// These changes use the original Work after its successful Apply fence.
	// The final fence must reject them and roll back the probe and mutation.
	switch p.mode {
	case "late-enrolled":
		_, err = w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=2,active_factors=1 WHERE tenant_id='tenant-a' AND user_id='user-a'`)
	case "late-unlinked":
		_, err = w.Exec(ctx, `UPDATE identity.accounts SET linked=false WHERE tenant_id='tenant-a' AND account_id='provider-account'`)
	}
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: p.op, BeforeVersion: 1, AfterVersion: 2}, nil
}

func (p *oneTapFactorInvocation) CheckFeatureCommit(ctx context.Context, w kernel.Work, command identity.Command) error {
	if err := p.check(ctx, w, command); err != nil {
		return err
	}
	p.final = true
	return nil
}

type oneTapFactorCapability struct{ plan kernel.CapabilityPlan }

func (*oneTapFactorCapability) Descriptor() kernel.ContributorDescriptor {
	return kernel.ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
}

func (*oneTapFactorCapability) RecoverParticipant(context.Context, kernel.RecoveryWork) (kernel.RecoveryStatus, error) {
	return kernel.RecoveryUnknown, nil
}

func (p *oneTapFactorCapability) ReserveCapability(ctx context.Context, w kernel.CapabilityReservationWork) error {
	b, err := w.Binding(p)
	if err != nil || b.Plan != p.plan || b.PreviousGeneration != 0 {
		return identity.ForbiddenError{}
	}
	n, err := w.Exec(ctx, `UPDATE onetap_factor_capability SET state='reserved',command_id=$2,fingerprint=$3,generation=$4::numeric
WHERE capability_id=$1 AND state='issued' AND expires_at=$5 AND expires_at>clock_timestamp()`, b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	return oneTapFactorCapabilityEffect(n, err)
}

func (*oneTapFactorCapability) RebindCapability(context.Context, kernel.CapabilityReservationWork) error {
	// This finite test never takes over a lease or substitutes a generation.
	return identity.ForbiddenError{}
}

type oneTapFactorCapabilitySQL interface {
	Exec(context.Context, string, ...any) (int64, error)
}

func (p *oneTapFactorCapability) transition(ctx context.Context, w oneTapFactorCapabilitySQL, b kernel.CapabilityReservationBinding, from, to string, previous uint64) error {
	if b.Plan != p.plan || b.Generation == 0 || previous == 0 {
		return identity.ForbiddenError{}
	}
	n, err := w.Exec(ctx, `UPDATE onetap_factor_capability SET state=$6,generation=$7::numeric
WHERE capability_id=$1 AND command_id=$2 AND fingerprint=$3 AND generation=$4::numeric AND state=$5 AND expires_at=$8 AND expires_at>clock_timestamp()`, b.Plan.CapabilityID, string(b.Command.CommandID), b.Fingerprint[:], strconv.FormatUint(previous, 10), from, to, strconv.FormatUint(b.Generation, 10), b.Plan.ExpiresAt)
	return oneTapFactorCapabilityEffect(n, err)
}

func oneTapFactorCapabilityEffect(n int64, err error) error {
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

func (p *oneTapFactorCapability) ApplyCapability(ctx context.Context, w kernel.CapabilityApplyWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	return p.transition(ctx, w, b, "reserved", "consumed", b.Generation)
}

func (p *oneTapFactorCapability) FinalizeCapability(ctx context.Context, w kernel.CapabilityFinalizeWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	return p.transition(ctx, w, b, "consumed", "finalized", b.Generation)
}

func (p *oneTapFactorCapability) ReleaseCapability(ctx context.Context, w kernel.CapabilityReleaseWork) error {
	b, err := w.Binding(p)
	if err != nil {
		return err
	}
	return p.transition(ctx, w, b, "reserved", "released", b.PreviousGeneration)
}

func TestOneTapCallbackFactorsPostgres(t *testing.T) {
	ctx, pool, repository := newOAuthSigninFactorStore(t)
	accounts := kernel.AccountMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	admission := kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: accounts, Version: 13}, Version: 14}
	counters := kernel.CounterPreparationMigrationSource{Base: admission, Version: 15}
	history, err := (kernel.OneTapCallbackPreparationErasureMigrationSource{Base: counters, Version: 16}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range history {
		if migration.Version() <= 14 {
			continue // The shared store already installed the original account/admission history.
		}
		if _, err := pool.Raw().Exec(ctx, migration.UpSQL()); err != nil {
			t.Fatal("actual One Tap preparation history", err)
		}
	}
	if _, err := pool.Raw().Exec(ctx, `WITH metadata AS (SELECT 'google'::text AS provider,'https://accounts.google.com'::text AS issuer,'opaque-subject'::text AS subject)
UPDATE identity.accounts a SET provider=m.provider,issuer=m.issuer,
subject_key=sha256(convert_to(octet_length(m.provider)::text||':'||m.provider||octet_length(m.issuer)::text||':'||m.issuer||octet_length(m.subject)::text||':'||m.subject,'UTF8'))
FROM metadata m WHERE a.tenant_id='tenant-a' AND a.account_id='provider-account';
CREATE TABLE onetap_factor_capability(capability_id text PRIMARY KEY,expires_at timestamptz NOT NULL,state text NOT NULL,command_id text,fingerprint bytea,generation numeric)`); err != nil {
		t.Fatal("existing Google account fixture", err)
	}
	account, err := repository.GetProviderSigninAccount(ctx, kernel.ProviderSigninAccountQuery{TenantID: "tenant-a", Provider: "google", Issuer: "https://accounts.google.com", Subject: "opaque-subject"})
	if err != nil || account.Account.UserID != "user-a" || account.Account.ID != "provider-account" {
		t.Fatal("exact existing Google account", err)
	}
	fields, err := kernel.OAuthSigninAccountFields(account)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"current", "missing", "enrolled", "stale", "unlinked", "changed-account", "late-enrolled", "late-unlinked"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, `DELETE FROM identity_mfa.factor_authorities;
INSERT INTO identity_mfa.factor_authorities VALUES('tenant-a','user-a',1,0,decode(repeat('01',16),'hex'),'identity.password.signup');
UPDATE identity.accounts SET linked=true,social_link_version=1 WHERE tenant_id='tenant-a' AND account_id='provider-account'`); err != nil {
				t.Fatal(err)
			}
			observed, err := ReadOAuthSigninFactors(ctx, pool, "tenant-a", "user-a", time.Second)
			if err != nil || observed.Version() != 1 {
				t.Fatal("original known-empty factor generation", err)
			}
			var mutation string
			switch mode {
			case "missing":
				mutation = `DELETE FROM identity_mfa.factor_authorities`
			case "enrolled":
				mutation = `UPDATE identity_mfa.factor_authorities SET active_factors=1`
			case "stale":
				mutation = `UPDATE identity_mfa.factor_authorities SET version=2`
			case "unlinked":
				mutation = `UPDATE identity.accounts SET linked=false WHERE tenant_id='tenant-a'`
			case "changed-account":
				mutation = `UPDATE identity.accounts SET social_link_version=2 WHERE tenant_id='tenant-a'`
			}
			if mutation != "" {
				if _, err := pool.Raw().Exec(ctx, mutation); err != nil {
					t.Fatal(err)
				}
			}
			id, _ := identity.NewCommandID()
			op := kernel.OneTapCallbackOperation()
			binding := identity.CommandBinding{CommandID: id, TenantID: "tenant-a", ActorID: "social-login", ActorKind: authorization.SubjectServiceAccount, AnonymousFlowID: string(id), RecordID: string(id), OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "onetap-signin", PolicyVersion: 1, CorrelationID: string(id)}
			command, err := identity.NewFeaturePreAuthCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: fields}, auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
			if err != nil {
				t.Fatal(err)
			}
			owner := &oneTapFactorInvocation{oauthSigninFactorInvocation: oauthSigninFactorInvocation{op: op, pool: pool, mode: mode}, expected: account}
			proof := &oneTapFactorCapability{plan: kernel.CapabilityPlan{CapabilityID: string(id), Purpose: "identity.oauth.onetap-callback", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: [32]byte{4}, ExpiresAt: time.Now().UTC().Truncate(time.Second).Add(4 * time.Minute), MaxUses: 1}}
			registry, err := kernel.NewContributorRegistry([]kernel.Contributor{repository, &signupFactorAudit{}, &signupFactorOutbox{}, owner, proof})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {2}}})
			if err != nil {
				t.Fatal(err)
			}
			builder, _ := audit.NewBuilder(audit.BuilderConfig{})
			seed, err := builder.Build(audit.RecordInput{OccurredAt: time.Now().UTC().Truncate(time.Microsecond), Action: "identity.oauth.verify_one_tap", Outcome: audit.OutcomeSucceeded, Actor: audit.ActorInput{Kind: audit.ActorService, ID: string(binding.ActorID)}, Subject: audit.SubjectInput{Type: "authentication_attempt", ID: binding.RecordID}, Context: audit.ContextInput{TenantID: string(binding.TenantID), CorrelationID: binding.CorrelationID}, Policy: audit.PolicyMetadata{PolicyID: binding.PolicyID, Version: "1"}, Changes: audit.ChangeSetInput{Redacted: true}, Attributes: map[string]string{"command.id": string(id), "aggregate.type": "authentication_attempt", "aggregate.id": binding.RecordID, "aggregate.before_version": "1", "aggregate.after_version": "2", "retention.class": "protected"}})
			if err != nil {
				t.Fatal(err)
			}
			digest, err := kernel.FeatureAuditBindingDigest(binding, op, "authentication_attempt", seed)
			if err != nil {
				t.Fatal(err)
			}
			declaration := kernel.CommandPlan{Contributors: registry.Descriptors(), SubjectType: "authentication_attempt", Feature: &kernel.FeatureRegistration{Contributor: owner.Descriptor(), Operation: op}, Capability: &proof.plan, Lifecycle: &kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 1, AfterVersion: 2}, Audits: []kernel.AuditPlan{{EventType: "identity.oauth.verify_one_tap", SchemaVersion: 1, BindingDigest: digest, RetentionClass: "protected", RetentionPolicyVersion: 1, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}}}
			owner.original, owner.declaration = command, declaration
			plan, err := coordinator.PrepareFeaturePreparationPlan(command, declaration)
			if err != nil {
				t.Fatal("prepare original one-use One Tap callback", err)
			}
			if _, err := pool.Raw().Exec(ctx, `INSERT INTO onetap_factor_capability(capability_id,expires_at,state) VALUES($1,$2,'issued')`, proof.plan.CapabilityID, proof.plan.ExpiresAt); err != nil {
				t.Fatal(err)
			}
			result, err := coordinator.ExecutePreparedFeature(ctx, command, plan)
			if owner.command != command {
				t.Fatal("original One Tap command did not reach real Apply", err)
			}
			success := mode == "current"
			if success && (err != nil || result.Outcome != identity.CommitOutcomeCommitted || !owner.applied || !owner.final || !owner.lockHeld) {
				t.Fatal("current exact Google callback did not commit with locked factors", result.Outcome, err)
			}
			if !success && (err == nil || result.Outcome == identity.CommitOutcomeCommitted || owner.final) {
				t.Fatal("ineligible authority admitted", result.Outcome, err)
			}
			if (mode == "late-enrolled" || mode == "late-unlinked") && !owner.applied {
				t.Fatal("late mutation did not reach the final fence", err)
			}
			if _, err := RequireOneTapCallbackFactors(ctx, owner.retained, owner, command, 1); err == nil {
				t.Fatal("returned Work retained factor authority")
			}
			var probes, events, succeeded int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM oauth_signin_factor_probe WHERE command_id=$1),(SELECT count(*) FROM signup_factor_events WHERE command_id=$1),(SELECT count(*) FROM signup_factor_audits WHERE command_id=$1 AND succeeded)`, string(id)).Scan(&probes, &events, &succeeded); err != nil {
				t.Fatal(err)
			}
			want := 0
			if success {
				want = 1
			}
			if probes != want || events != want || succeeded != want {
				t.Fatal("domain, lifecycle or success audit escaped rollback", probes, events, succeeded)
			}
			var state string
			if err := pool.Raw().QueryRow(ctx, `SELECT state FROM onetap_factor_capability WHERE capability_id=$1`, proof.plan.CapabilityID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if success && state != "finalized" || !success && state != "released" {
				t.Fatal("one-use state did not share commit/rollback", state)
			}
			if mode == "missing" {
				var authorities int
				if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_mfa.factor_authorities WHERE tenant_id='tenant-a' AND user_id='user-a'`).Scan(&authorities); err != nil || authorities != 0 {
					t.Fatal("missing factor authority was initialized by callback", authorities, err)
				}
			}
			if mode == "late-enrolled" {
				var version, active int
				if err := pool.Raw().QueryRow(ctx, `SELECT version,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id='tenant-a' AND user_id='user-a'`).Scan(&version, &active); err != nil || version != 1 || active != 0 {
					t.Fatal("late enrollment survived rollback", version, active, err)
				}
			}
			if mode == "late-unlinked" {
				var linked bool
				if err := pool.Raw().QueryRow(ctx, `SELECT linked FROM identity.accounts WHERE tenant_id='tenant-a' AND account_id='provider-account'`).Scan(&linked); err != nil || !linked {
					t.Fatal("late unlink survived rollback", err)
				}
			}
		})
	}
}
