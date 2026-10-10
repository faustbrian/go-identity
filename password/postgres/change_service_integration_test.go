//go:build integration

package passwordpostgres_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
)

// Real primary owners, signed-original authentication engine, crypto, protected
// counters, proof/material/kernel/audit/outbox SQL all run. Only provider facts
// are a deliberate external HIBP seam; this is not live-provider interoperability.
func testNativePasswordChange(t *testing.T, ctx context.Context, pool *database.Pool, sourceConfig passworddb.ReauthenticationConfig, source *passworddb.ReauthenticationService, verification passworddb.ReauthenticationRequest) {
	t.Helper()
	// Risk plan: public possession/proof consumption, exact effective versions,
	// all three session choices, cap rollback, original-history preservation,
	// repeat changes through a preserved bearer, and original recovery after
	// restart. Existing ambiguity/cancellation/audit/outbox tests remain active.
	for _, migration := range []migrations.Source{
		sessionpg.OTPMigrationSource{Schema: sourceConfig.Session.Schema, Version: 3},
		sessionpg.CredentialContinuationMigrationSource{Schema: sourceConfig.Session.Schema, Version: 4},
		sessionpg.PasswordChangeMigrationSource{Schema: sourceConfig.Session.Schema, Version: 5},
	} {
		items, e := migration.Load(ctx)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range items {
			if _, e = pool.Raw().Exec(ctx, item.UpSQL()); e != nil {
				t.Fatal("password session migration", e)
			}
		}
	}
	sessions, err := sessionpg.NewRepository(pool, sourceConfig.Session)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := sessions.Get(ctx, verification.TenantID, "reauth-session")
	if err != nil {
		t.Fatal(err)
	}
	initialSpec, _ := initial.Session.Bindings()
	// A second eligible password session shares the existing family, but has
	// independent bearer and session scope. Only synthetic test custody is stored.
	otherSpec := initialSpec
	otherSpec.SessionID = "reauth-other-session"
	token, _ := session.ParseToken(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{47}, 32)))
	otherSpec.Lookup, err = token.Digest(sourceConfig.LookupKeys[0], string(verification.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	vector, _ := otherSpec.Authority.Bindings()
	keys, _ := sessionpg.SessionAuthorityKeys(otherSpec.TenantID, otherSpec.UserID, otherSpec.FamilyID, otherSpec.SessionID)
	vector.Session.ScopeKey = keys.Session
	otherSpec.Authority, err = session.NewAuthoritySnapshot(vector)
	if err != nil {
		t.Fatal(err)
	}
	other, err := session.NewSession(otherSpec)
	if err != nil {
		t.Fatal(err)
	}
	remember, _ := otherSpec.Remember.Bindings()
	encoded, err := json.Marshal(map[string]any{"Schema": 1, "SessionID": otherSpec.SessionID, "FamilyID": otherSpec.FamilyID, "TenantID": otherSpec.TenantID, "UserID": otherSpec.UserID, "Audience": otherSpec.Audience, "Version": otherSpec.Version, "FamilyVersion": otherSpec.FamilyVersion, "Remember": remember, "Authority": vector, "Lookup": otherSpec.Lookup, "Authentication": otherSpec.Authentication, "IssuedAt": otherSpec.IssuedAt, "LastActivityAt": otherSpec.LastActivityAt})
	if err != nil {
		t.Fatal(err)
	}
	// Existing physical column constraints and public reconstruction validate
	// the fixture before any consuming password operation.
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO reauth_sessions.sessions SELECT tenant_id,$1,user_id,family_id,version,family_version,'active',$2,$3,expires_at,$4::jsonb FROM reauth_sessions.sessions WHERE session_id='reauth-session'`, otherSpec.SessionID, otherSpec.Lookup.KeyVersion, otherSpec.Lookup.Sum[:], encoded); err != nil {
		t.Fatal("other session fixture", err)
	}
	if got, e := sessions.Get(ctx, verification.TenantID, otherSpec.SessionID); e != nil || got.Session.EffectiveCredentialVersion() != other.EffectiveCredentialVersion() {
		t.Fatal("other session reconstruction", e)
	}
	history, err := (riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "password_risk", Version: 20}, Version: 21}, Version: 22}, Version: 23}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range history {
		if _, err = pool.Raw().Exec(ctx, m.UpSQL()); err != nil {
			t.Fatal("counter migration failed", err)
		}
	}
	profiles := []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status"}},
	}
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, HIBP: risk.HIBPPolicy{CacheTTL: time.Hour, Operations: []risk.Action{"identity.password.change"}}, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: profiles})
	if err != nil {
		t.Fatal("password-change policy", err)
	}
	key, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{41}, 32))
	evidence, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{42}, 32), bytes.Repeat([]byte{43}, 32))
	counters, err := riskpg.NewRepository(riskpg.Config{Schema: "password_risk", PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"wrap_v1": bytes.Repeat([]byte{44}, 32)}, CurrentEnvelopeKey: "wrap_v1", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{key}}})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	var scenario atomic.Int32
	var collectionMu sync.Mutex
	collected := make(map[string]bool)
	var repeated atomic.Bool
	config := passworddb.PasswordChangeConfig{Audience: "backend", MaximumAge: 5 * time.Minute, Counters: counters, Screening: password.HashPreparationConfig{Primitive: sourceConfig.Verifier.Primitive, MinimumBytes: 8, MaximumBytes: 128, Timeout: time.Second, DummyHash: sourceConfig.Verifier.DummyHash, Policy: policy, Now: time.Now, Collect: func(ctx context.Context, c risk.Context, candidate primitive.Secret) ([]risk.Signal, error) {
		calls.Add(1)
		collectionMu.Lock()
		if collected[c.Attempt] {
			repeated.Store(true)
		}
		collected[c.Attempt] = true
		collectionMu.Unlock()
		observation := risk.PasswordObservation{ObservedAt: c.Now, CheckedAt: c.Now, ValidUntil: c.Now.Add(time.Hour)}
		if scenario.Load() == 1 {
			observation.BreachCount = 1
		}
		if scenario.Load() == 2 {
			observation = risk.PasswordObservation{Failure: risk.ProviderUnavailable}
		}
		hibp, e := policy.PasswordSignal(ctx, c, observation)
		if e != nil {
			return nil, e
		}
		return []risk.Signal{{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(time.Minute)}, hibp}, nil
	}}}
	// The public service must compose the native effect, not merely invalidate
	// the independent credential epoch and leave preservation to application SQL.
	config.SessionDisposition = sessionpg.PasswordChangePreserveSessions
	config.MaximumSessions = 16
	change, err := passworddb.NewPasswordChangeService(source, config)
	if err != nil {
		t.Fatal("native change composition failed", err)
	}
	issued, err := source.Verify(ctx, verification)
	if err != nil || issued.Proof.Proof.ID == "" {
		t.Fatal("original proof issuance failed", err)
	}
	secret, _ := primitive.NewSecret([]byte("new-synthetic-test-password"))
	defer secret.Destroy()
	request := passworddb.PasswordChangeRequest{TenantID: verification.TenantID, Session: verification.Session, Proof: issued.Proof, Password: secret, Caller: verification.Caller, Network: verification.Network}
	for _, kind := range []string{"reuse", "foreign-proof", "wrong-action", "wrong-audience", "wrong-session-version", "altered-time", "foreign-tenant", "foreign-caller", "breached", "outage", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			r := request
			call := ctx
			switch kind {
			case "reuse":
				r.Password = verification.Password
			case "foreign-proof":
				r.Proof.Proof.Subject = "other"
			case "wrong-action":
				r.Proof.Action = "identity.password.set"
			case "wrong-audience":
				r.Proof.Proof.Audience = "foreign"
			case "wrong-session-version":
				r.Proof.SessionVersion++
			case "altered-time":
				r.Proof.Proof.IssuedAt = r.Proof.Proof.IssuedAt.Add(time.Second)
			case "foreign-tenant":
				r.TenantID = "foreign"
			case "foreign-caller":
				r.Caller = r.Caller.Clone()
				r.Caller.Request.Subject.ID = "foreign"
			case "breached":
				scenario.Store(1)
			case "outage":
				scenario.Store(2)
			case "cancelled":
				var cancel context.CancelFunc
				call, cancel = context.WithCancel(ctx)
				cancel()
			}
			defer scenario.Store(0)
			out, e := change.Change(call, r)
			if e == nil || out.Outcome == identity.CommitOutcomeCommitted || out.CredentialVersion != 0 {
				t.Fatal("denied input mutated password", kind, e)
			}
			if kind == "cancelled" && !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation lost", e)
			}
		})
	}
	t.Run("expiry-after-proof-lock", func(t *testing.T) {
		short := config
		short.MaximumAge = 500 * time.Millisecond
		service, e := passworddb.NewPasswordChangeService(source, short)
		if e != nil {
			t.Fatal(e)
		}
		fresh, e := source.Verify(ctx, verification)
		if e != nil || fresh.Proof.Proof.ID == "" {
			t.Fatal("fresh lock-test proof failed", e)
		}
		tx, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal("proof lock unavailable")
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup)
		}()
		if _, e = tx.Exec(ctx, `SELECT proof_id FROM identity_password.reauthentication_records WHERE proof_id=$1 FOR UPDATE`, string(fresh.Proof.Proof.ID)); e != nil {
			t.Fatal("proof lock failed")
		}
		r := request
		r.Proof = fresh.Proof
		result, e := service.Change(ctx, r)
		if !errors.Is(e, context.DeadlineExceeded) || result.CommandID == "" || result.Outcome == identity.CommitOutcomeCommitted || result.CredentialVersion != 0 || result.AuthorityInvalidated {
			t.Fatal("original proof deadline lost under lock", e, result.Outcome)
		}
		if e = tx.Rollback(ctx); e != nil {
			t.Fatal("proof lock cleanup failed")
		}
		var consumed bool
		var materialVersion string
		if e = pool.Raw().QueryRow(ctx, `SELECT p.consumed_command_id IS NOT NULL,c.version::text FROM identity_password.reauthentication_records p JOIN identity_password.credentials c USING(tenant_id,user_id) WHERE p.proof_id=$1`, string(fresh.Proof.Proof.ID)).Scan(&consumed, &materialVersion); e != nil || consumed || materialVersion != "7" {
			t.Fatal("expired use changed material or consumed proof", e)
		}
	})
	// A real outbox write failure must roll back one-use consumption, material,
	// both kernel versions and lifecycle. The charged attempt remains retained.
	if _, err = pool.Raw().Exec(ctx, `CREATE FUNCTION identity_password.reject_change_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic change effect failure'; END $$;CREATE TRIGGER reject_change_effect BEFORE INSERT ON public.identity_outbox_bindings FOR EACH ROW EXECUTE FUNCTION identity_password.reject_change_effect()`); err != nil {
		t.Fatal(err)
	}
	failed, err := change.Change(ctx, request)
	if _, e := pool.Raw().Exec(ctx, `DROP TRIGGER reject_change_effect ON public.identity_outbox_bindings;DROP FUNCTION identity_password.reject_change_effect()`); e != nil {
		t.Fatal("trigger cleanup failed", e)
	}
	if err == nil || failed.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("outbox rollback classification", err, failed.Outcome)
	}
	var consumed bool
	var version, epoch string
	if err = pool.Raw().QueryRow(ctx, `SELECT p.consumed_command_id IS NOT NULL,c.version::text,u.credential_version::text FROM identity_password.reauthentication_records p JOIN identity.users u ON u.tenant_id=p.tenant_id AND u.user_id=p.user_id JOIN identity_password.credentials c ON c.tenant_id=u.tenant_id AND c.user_id=u.user_id WHERE p.proof_id=$1`, string(issued.Proof.Proof.ID)).Scan(&consumed, &version, &epoch); err != nil || consumed || version != "7" || epoch != "5" {
		t.Fatal("rollback leaked protected state", err)
	}
	newFaultService := func(before bool) (*passworddb.PasswordChangeService, *reauthenticationCommitFault) {
		fault := &reauthenticationCommitFault{before: before, marker: []byte("UPDATE identity_password.reauthentication_records SET consumed_command_id")}
		faultPool, e := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error { c.ConnConfig.DialFunc = fault.dial; return nil }})
		if e != nil {
			t.Fatal("change fault pool unavailable")
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			if faultPool.Close(cleanup) != nil {
				t.Error("fault pool cleanup failed")
			}
		})
		c := sourceConfig
		c.Coordinator.LeaseDuration = 500 * time.Millisecond
		native, e := passworddb.NewReauthenticationService(faultPool, c)
		if e != nil {
			t.Fatal("fault source composition failed", e)
		}
		service, e := passworddb.NewPasswordChangeService(native, config)
		if e != nil {
			t.Fatal("change fault composition failed", e)
		}
		return service, fault
	}
	queryFor := func(id identity.CommandID) identity.RecoveryQuery {
		return identity.RecoveryQuery{CommandID: id, TenantID: request.TenantID, UserID: identity.UserID(request.Caller.Request.Subject.ID), ActorID: identity.ActorID(request.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.password.change", RecordID: "reauth-password"}
	}
	t.Run("disconnect-before-commit", func(t *testing.T) {
		service, fault := newFaultService(true)
		original, e := service.Change(ctx, request)
		if e == nil || !fault.hit.Load() || original.Outcome != identity.CommitOutcomeUnknown || original.CommandID == "" || original.CredentialVersion != 0 || original.AuthorityInvalidated {
			t.Fatal("precommit disconnect fabricated success", e, original.Outcome)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(original.CommandID))
		var effects int
		if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_command_id=$1)+(SELECT count(*) FROM identity_password.replacements WHERE command_id=$1)+(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, id).Scan(&effects); e != nil || effects != 0 {
			t.Fatal("precommit disconnect retained protected effects", e)
		}
		bounded, stop := context.WithTimeout(ctx, 3*time.Second)
		defer stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		before := calls.Load()
		for {
			result, e := change.Recover(bounded, queryFor(original.CommandID), request.Caller)
			if result.CredentialVersion != 0 || result.AuthorityInvalidated || calls.Load() != before {
				t.Fatal("recovery fabricated authority or repeated provider")
			}
			if result.Outcome == identity.CommitOutcomeNotCommitted {
				break
			}
			select {
			case <-bounded.Done():
				t.Fatal("precommit outcome unresolved", e)
			case <-ticker.C:
			}
		}
	})
	before := calls.Load()
	// Both callers compete through the real primary. The winner loses only its
	// COMMIT acknowledgement; independent SQL and code-free recovery must identify
	// the original winner without resubmitting its password or consuming again.
	service, afterFault := newFaultService(false)
	var contenders [2]passworddb.PasswordChangeResult
	var failures [2]error
	var group sync.WaitGroup
	for i := range contenders {
		candidate, e := primitive.NewSecret([]byte("new-synthetic-test-password"))
		if e != nil {
			t.Fatal("independent change secret unavailable")
		}
		r := request
		r.Password = candidate
		group.Go(func() {
			defer candidate.Destroy()
			contenders[i], failures[i] = service.Change(ctx, r)
		})
	}
	group.Wait()
	var committed passworddb.PasswordChangeResult
	winners := 0
	for i, result := range contenders {
		if result.Outcome == identity.CommitOutcomeUnknown {
			if failures[i] == nil || result.CredentialVersion != 0 || result.AuthorityInvalidated {
				t.Fatal("lost acknowledgement disclosed success")
			}
			var e error
			result, e = change.Recover(ctx, queryFor(result.CommandID), request.Caller)
			if e != nil {
				t.Fatal("postcommit recovery failed", e)
			}
			failures[i] = nil
		}
		if result.Outcome == identity.CommitOutcomeCommitted {
			if failures[i] != nil || result.CredentialVersion != 8 || !result.AuthorityInvalidated {
				t.Fatal("native committed change failed", failures[i])
			}
			committed, winners = result, winners+1
		} else if failures[i] == nil || result.CredentialVersion != 0 || result.AuthorityInvalidated {
			t.Fatal("competing proof use was not denied", failures[i])
		}
	}
	if winners != 1 || !afterFault.hit.Load() {
		t.Fatal("one-use proof did not have exactly one winner")
	}
	if calls.Load() < before+1 || calls.Load() > before+2 {
		t.Fatal("provider preparation repeated")
	}
	id, _ := base64.RawURLEncoding.Strict().DecodeString(string(committed.CommandID))
	var proofRows, materialRows, audits, outboxes, sessionEffects int
	if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records WHERE consumed_command_id=$1),(SELECT count(*) FROM identity_password.replacements WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1),(SELECT count(*) FROM reauth_sessions.password_changes WHERE command_id=$1 AND disposition=1 AND preserved_count=2 AND revoked_count=0)`, id).Scan(&proofRows, &materialRows, &audits, &outboxes, &sessionEffects); err != nil || proofRows != 1 || materialRows != 1 || audits != 1 || outboxes != 1 || sessionEffects != 1 {
		t.Fatal("protected effects not atomic", err)
	}
	var profile, beforeUser, afterUser, beforeAuthority, afterAuthority, beforeCredential, afterCredential string
	if err = pool.Raw().QueryRow(ctx, `SELECT p->>'profile',p->>'before_user_version',p->>'after_user_version',p->>'before_authority_version',p->>'after_authority_version',p->'lifecycle'->>'before_version',p->'lifecycle'->>'after_version' FROM (SELECT convert_from(m.payload,'UTF8')::jsonb p FROM public.outbox_messages m JOIN public.identity_outbox_bindings b ON b.effect_id=m.id WHERE b.command_id=$1) original`, id).Scan(&profile, &beforeUser, &afterUser, &beforeAuthority, &afterAuthority, &beforeCredential, &afterCredential); err != nil || profile != "identity-credential-replacement-v1" || beforeUser != "9" || afterUser != "10" || beforeAuthority != "5" || afterAuthority != "6" || beforeCredential != "7" || afterCredential != "8" {
		t.Fatal("outbox lost independent authority successors", err)
	}
	repository, _ := passworddb.NewRepository(pool, sourceConfig.Repository)
	current, err := repository.ReadPasswordCredential(ctx, password.CredentialKey{TenantID: request.TenantID, SubjectID: identity.UserID(request.Caller.Request.Subject.ID)})
	if err != nil || current.Authority().Credential.Version != 8 || current.Authority().AuthorityVersion != 6 || current.Authority().User.Version != 10 {
		t.Fatal("kernel/material successors diverged", err)
	}
	match, err := sourceConfig.Verifier.Primitive.Verify(ctx, []byte("new-synthetic-test-password"), current.EncodedHash().String())
	if err != nil || !match.Match() {
		t.Fatal("new password unusable", err)
	}
	match, err = sourceConfig.Verifier.Primitive.Verify(ctx, []byte("synthetic-test-password"), current.EncodedHash().String())
	if !errors.Is(err, primitive.ErrMismatch) || match.Match() {
		t.Fatal("old password still usable", err)
	}
	// Preserved sessions keep historical proof/version and timing, but must use
	// the exact new effective reference and epoch for future protected use.
	for _, id := range []string{initialSpec.SessionID, otherSpec.SessionID} {
		stored, e := sessions.Get(ctx, verification.TenantID, id)
		if e != nil || stored.Revoked || stored.Session.EffectiveCredentialVersion() != 8 {
			t.Fatal("configured preservation lost current session authority", e)
		}
		spec, _ := stored.Session.Bindings()
		if spec.Authentication != initialSpec.Authentication || spec.IssuedAt != initialSpec.IssuedAt || spec.LastActivityAt != initialSpec.LastActivityAt || spec.Version != initialSpec.Version || spec.FamilyVersion != initialSpec.FamilyVersion {
			t.Fatal("continuation manufactured fresh login history")
		}
	}
	denied, e := source.Verify(ctx, verification)
	if e == nil && denied.Proof.Proof.ID != "" {
		t.Fatal("old source session issued a new proof")
	}
	retained, err := repository.Reauthentication(ctx, issued.Proof.Proof.ID)
	if err != nil || retained.Proof != issued.Proof {
		t.Fatal("consumption rewrote original proof", err)
	}
	q := identity.RecoveryQuery{CommandID: committed.CommandID, TenantID: request.TenantID, UserID: identity.UserID(request.Caller.Request.Subject.ID), ActorID: identity.ActorID(request.Caller.Request.Subject.ID), ActorKind: authorization.SubjectUser, OperationID: "identity.password.change", RecordID: "reauth-password"}
	restarted, err := passworddb.NewPasswordChangeService(source, config)
	if err != nil {
		t.Fatal(err)
	}
	before = calls.Load()
	recovered, err := restarted.Recover(ctx, q, request.Caller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.CredentialVersion != 8 || calls.Load() != before {
		t.Fatal("original recovery renewed work or lost receipt", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	deniedRecovery, err := restarted.Recover(cancelled, q, request.Caller)
	if !errors.Is(err, context.Canceled) || deniedRecovery.CredentialVersion != 0 || deniedRecovery.AuthorityInvalidated || calls.Load() != before {
		t.Fatal("cancelled recovery disclosed authority or renewed provider work", err)
	}
	if repeated.Load() {
		t.Fatal("provider collection repeated within one attempt")
	}
	// A new proof over the unchanged bearer and new password must bind effective
	// version8, not historical login version7. Cap failure leaves it unconsumed.
	// Put only the synthetic current windows in an expired fixture state; retain
	// every original charge/snapshot. This is not a risk refund or timing oracle.
	// Otherwise the preceding deliberate failure attempts exhaust the real limit
	// before the independently targeted session-cap behavior is reached.
	if _, e := pool.Raw().Exec(ctx, `UPDATE password_risk.counter_windows SET started_at=started_at-interval '15 minutes',expires_at=expires_at-interval '15 minutes' WHERE tenant_id=$1 AND operation='identity.password.change'`, string(request.TenantID)); e != nil {
		t.Fatal("expired risk-window fixture", e)
	}
	verification.Password = secret
	fresh, e := source.Verify(ctx, verification)
	if e != nil || fresh.Proof.Proof.ID == "" {
		t.Fatal("continued bearer could not reauthenticate", e)
	}
	secondSecret, _ := primitive.NewSecret([]byte("second-synthetic-test-password"))
	defer secondSecret.Destroy()
	second := request
	second.Password, second.Proof = secondSecret, fresh.Proof
	limited := config
	limited.MaximumSessions = 1
	limitedService, e := passworddb.NewPasswordChangeService(source, limited)
	if e != nil {
		t.Fatal(e)
	}
	limitResult, limitError := limitedService.Change(ctx, second)
	if limitError == nil || limitResult.Outcome != identity.CommitOutcomeNotCommitted || limitResult.CredentialVersion != 0 || limitResult.CommandID == "" {
		t.Fatal("whole-set limit did not deny public password change", limitError)
	}
	limitID, _ := base64.RawURLEncoding.Strict().DecodeString(string(limitResult.CommandID))
	var admittedCounters int
	if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM password_risk.counter_snapshots WHERE command_id=$1 AND value=1`, limitID).Scan(&admittedCounters); e != nil || admittedCounters != 4 {
		t.Fatal("session-cap test did not reach admitted native Work", e)
	}
	for _, id := range []string{initialSpec.SessionID, otherSpec.SessionID} {
		stored, e := sessions.Get(ctx, verification.TenantID, id)
		if e != nil || stored.Revoked || stored.Session.EffectiveCredentialVersion() != 8 {
			t.Fatal("limit failure left a partial session effect", e)
		}
	}
	config.SessionDisposition = sessionpg.PasswordChangeRevokeOtherSessions
	otherService, e := passworddb.NewPasswordChangeService(source, config)
	if e != nil {
		t.Fatal(e)
	}
	changed, e := otherService.Change(ctx, second)
	if e != nil || changed.Outcome != identity.CommitOutcomeCommitted || changed.CredentialVersion != 9 {
		t.Fatal("same proof could not survive whole-set rollback", e)
	}
	kept, e := sessions.Get(ctx, verification.TenantID, initialSpec.SessionID)
	if e != nil || kept.Revoked || kept.Session.EffectiveCredentialVersion() != 9 {
		t.Fatal("revoke-other lost original source", e)
	}
	revoked, e := sessions.Get(ctx, verification.TenantID, otherSpec.SessionID)
	if e != nil || !revoked.Revoked || revoked.Session.EffectiveCredentialVersion() != 8 {
		t.Fatal("revoke-other preserved a competing session", e)
	}
	verification.Password = secondSecret
	lastProof, e := source.Verify(ctx, verification)
	if e != nil || lastProof.Proof.Proof.ID == "" {
		t.Fatal("twice-continued bearer could not reauthenticate", e)
	}
	lastSecret, _ := primitive.NewSecret([]byte("third-synthetic-test-password"))
	defer lastSecret.Destroy()
	last := request
	last.Proof, last.Password = lastProof.Proof, lastSecret
	// Zero configuration selects strict revoke-all, not implicit preservation.
	config.SessionDisposition, config.MaximumSessions = 0, 0
	allService, e := passworddb.NewPasswordChangeService(source, config)
	if e != nil {
		t.Fatal(e)
	}
	lastResult, finalPassword := testNativeKeyedPasswordChange(t, ctx, pool, source, sourceConfig, config, last, &calls)
	defer finalPassword.Destroy()
	if lastResult.Outcome != identity.CommitOutcomeCommitted || lastResult.CredentialVersion != 11 {
		t.Fatal("default strict password change failed", e)
	}
	kept, e = sessions.Get(ctx, verification.TenantID, initialSpec.SessionID)
	if e != nil || !kept.Revoked || kept.Session.EffectiveCredentialVersion() != 10 {
		t.Fatal("default failed to terminally revoke source", e)
	}
	// Probe revocation with the actual committed password, not the preceding
	// cookie password: a mismatch must not hide a broken revocation effect.
	verification.Password = finalPassword
	if out, e := source.Verify(ctx, verification); e == nil || out.Proof.Proof.ID != "" {
		t.Fatal("revoked bearer issued a new proof", e)
	}
	// Outcome disclosure follows the original command, not the new startup choice
	// or current material/session state. Payload pruning must not erase custody.
	if _, e := pool.Raw().Exec(ctx, `DELETE FROM reauth_sessions.sessions WHERE tenant_id=$1 AND user_id=$2`, string(request.TenantID), string(initialSpec.UserID)); e != nil {
		t.Fatal("synthetic payload cleanup", e)
	}
	before = calls.Load()
	if out, e := allService.Recover(ctx, q, request.Caller); e != nil || out.Outcome != identity.CommitOutcomeCommitted || out.CredentialVersion != 8 || calls.Load() != before {
		t.Fatal("original outcome depended on current session policy/payload", e)
	}
	if repeated.Load() {
		t.Fatal("provider collection repeated within one attempt")
	}
}
