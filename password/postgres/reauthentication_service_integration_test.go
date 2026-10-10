//go:build integration

package passwordpostgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	passworddb "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
)

// Counter/audit delivery doubles exist only at their external risk boundaries.
// All proof, session, kernel, security audit and lifecycle SQL owners are real.
type reauthenticationRiskFixture struct {
	charges, deliveries atomic.Int64
	throttle            atomic.Bool
	outage              atomic.Bool
}

func (f *reauthenticationRiskFixture) Mutate(_ context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	f.charges.Add(1)
	if f.outage.Load() {
		return risk.CounterResult{}, errors.New("synthetic unavailable")
	}
	b := c.Bindings()
	var counters []risk.Counter
	value := uint64(1)
	if f.throttle.Load() {
		value = b.Limit + 1
	}
	for _, target := range b.Targets {
		counters = append(counters, risk.Counter{Kind: string(target.Dimension), Value: value, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt.Add(-time.Second), WindowExpiresAt: b.PreparedAt.Add(b.Window - time.Second)})
	}
	return risk.NewCounterResult(c, risk.CounterCommitted, counters)
}
func (f *reauthenticationRiskFixture) Append(_ context.Context, r audit.Record) (audit.AppendResult, error) {
	f.deliveries.Add(1)
	return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
}

func (*reauthenticationRiskFixture) AppendBatch(context.Context, []audit.Record) (audit.BatchResult, error) {
	return audit.BatchResult{}, errors.New("unexpected batch delivery")
}

func reauthenticationRisk(t *testing.T, f *reauthenticationRiskFixture) risk.AuthenticationAdmissionCustodyConfig {
	t.Helper()
	pc := risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}}
	policy, err := risk.NewPolicy(pc)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{31}, 32))
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Store: f, Clock: time.Now, Timeout: time.Second, Keys: []risk.CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := identity.NewCommandID()
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: 2 * time.Second, Counters: &counters,
		Sources: []risk.Source{{Name: "status", Version: "native-test-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
			return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(30 * time.Second)}, nil
		}}},
		DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(policyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: f, Mode: audit.DeliveryFailClosed}, OnLoss: func(context.Context, risk.DecisionDelivery) error { return nil }},
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{32}, 32), bytes.Repeat([]byte{33}, 32))
	return risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "native-reauth-test-v1", Keys: []risk.EvidenceKey{evidence}}
}

func testNativeReauthenticationService(t *testing.T, ctx context.Context, pool *database.Pool, policy primitive.Policy, crypto *primitive.Service, hash primitive.EncodedHash) {
	t.Helper()
	base := kernel.CredentialReplacementMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	history, err := (kernel.DirectoryAuthorityMigrationSource{Base: base, Version: 13, GlobalAuthorityID: "reauth-deployment", TenantIDs: []identity.TenantID{"AAAAAAAAAAAAAAAAAAAAAQ"}}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, history[len(history)-1].UpSQL()); err != nil {
		t.Fatal("directory migration failed", err)
	}
	source, err := (sessionpg.MigrationSource{Schema: "reauth_sessions", Version: 1}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, source[0].UpSQL()); err != nil {
		t.Fatal("session migration failed", err)
	}
	if _, err = pool.Raw().Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
		t.Fatal("audit installation failed", err)
	}
	for _, source := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), lifecyclepg.Migrations()} {
		files, err := fs.ReadDir(source, ".")
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			wire, err := fs.ReadFile(source, file.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
				t.Fatal("native effect migration failed", err)
			}
		}
	}
	m, err := authoritypg.AuthoritySchemaMigration(300)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, m.Up); err != nil {
		t.Fatal("authorization migration failed", err)
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version,authority_version,identifier_version,credential_version) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','active',9,3,4,5);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','reauth-password',1,'identity/password',7,true);
INSERT INTO authorization_subject_authorities VALUES('AAAAAAAAAAAAAAAAAAAAAQ','users','AAAAAAAAAAAAAAAAAAAAAg',8)`); err != nil {
		t.Fatal("native owners failed", err)
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','reauth-password',7,'argon2id',$1)`, hash.String()); err != nil {
		t.Fatal("material fixture failed")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: 5 * time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: "reauth-deployment", TenantID: "AAAAAAAAAAAAAAAAAAAAAQ"}, "AAAAAAAAAAAAAAAAAAAAAg")
	skeys, _ := sessionpg.SessionAuthorityKeys("AAAAAAAAAAAAAAAAAAAAAQ", "AAAAAAAAAAAAAAAAAAAAAg", "reauth-family", "reauth-session")
	akey, _ := (authoritypg.AuthorityScope{TenantID: "AAAAAAAAAAAAAAAAAAAAAQ", SubjectID: "AAAAAAAAAAAAAAAAAAAAAg", PolicyNamespace: "users"}).Key()
	binding := func(k string, v uint64) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: k, Version: v}
	}
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: binding(keys.Global, 1), Tenant: binding(keys.Tenant, 1), User: binding(keys.User, 3), Identifier: binding(keys.Identifier, 4), Credential: binding(keys.Credential, 5), Session: binding(skeys.Session, 1), SessionFamily: binding(skeys.Family, 1), Authorization: binding(akey, 8)})
	if err != nil {
		t.Fatal(err)
	}
	lookupKey, _ := session.NewDigestKey(1, bytes.Repeat([]byte{37}, 32))
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{38}, 32))
	token, _ := session.ParseToken(wire)
	digest, _ := token.Digest(lookupKey, "AAAAAAAAAAAAAAAAAAAAAQ")
	original, err := session.NewSession(session.SessionSpec{SessionID: "reauth-session", FamilyID: "reauth-family", TenantID: "AAAAAAAAAAAAAAAAAAAAAQ", UserID: "AAAAAAAAAAAAAAAAAAAAAg", Audience: "backend", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "aaaaaaaaaaaaaaaaaaaaaa", Tenant: "AAAAAAAAAAAAAAAAAAAAAQ", Subject: "AAAAAAAAAAAAAAAAAAAAAg", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "backend", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "reauth-password", CredentialVersion: 7}, IssuedAt: now, LastActivityAt: now})
	if err != nil {
		t.Fatal(err)
	}
	s, _ := original.Bindings()
	rem, _ := remember.Bindings()
	vector, _ := authority.Bindings()
	lifetime, _ := original.Lifetime(now)
	payload, _ := json.Marshal(map[string]any{"Schema": 1, "SessionID": s.SessionID, "FamilyID": s.FamilyID, "TenantID": s.TenantID, "UserID": s.UserID, "Audience": s.Audience, "Version": s.Version, "FamilyVersion": s.FamilyVersion, "Remember": rem, "Authority": vector, "Lookup": s.Lookup, "Authentication": s.Authentication, "IssuedAt": s.IssuedAt, "LastActivityAt": s.LastActivityAt})
	const instant = "2006-01-02T15:04:05.000000000Z"
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO reauth_sessions.families VALUES($1,$2,$3,$4,'active',$5)`, string(s.TenantID), s.FamilyID, string(s.UserID), s.FamilyVersion, s.IssuedAt.Format(instant)); err != nil {
		t.Fatal("source family failed", err)
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO reauth_sessions.sessions VALUES($1,$2,$3,$4,$5,$6,'active',$7,$8,$9,$10::jsonb)`, string(s.TenantID), s.SessionID, string(s.UserID), s.FamilyID, s.Version, s.FamilyVersion, s.Lookup.KeyVersion, s.Lookup.Sum[:], lifetime.ExpiresAt.Format(instant), payload); err != nil {
		t.Fatal("source session failed", err)
	}
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{39}, 32))
	public := bytes.Clone(private.Public().(ed25519.PublicKey))
	signer, err := passworddb.NewReauthenticationSigningKey("evidence-1", private)
	clear(private)
	if err != nil {
		t.Fatal(err)
	}
	riskFixture := &reauthenticationRiskFixture{}
	configuration := passworddb.ReauthenticationConfig{Repository: passworddb.Config{MaximumDuration: 3 * time.Second, HashPolicy: policy}, Verifier: password.VerifierConfig{Primitive: crypto, MaximumBytes: 128, Timeout: time.Second, DummyHash: hash, Now: time.Now}, Session: sessionpg.Config{Schema: "reauth_sessions", MaximumDuration: time.Second}, Profile: sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "reauth-deployment", PolicyNamespace: "users", Audience: "backend", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}, LookupKeys: []session.DigestKey{lookupKey}, Risk: reauthenticationRisk(t, riskFixture), Coordinator: kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}, QueryPolicy: &kernel.CommandQueryPolicy{Clock: clock.System{}, PolicyVersion: 9, Authorization: passwordQueryPolicy{}}}, SigningKey: signer, VerificationKeys: map[string]ed25519.PublicKey{"evidence-1": public}, Issuer: "issuer", Environment: "test", Targets: []passworddb.ReauthenticationTarget{{Purpose: "identity.password.verify", Action: "identity.password.change", Audience: "backend"}}, TTL: 5 * time.Minute, IdentifierKey: bytes.Repeat([]byte{40}, 32)}
	service, err := passworddb.NewReauthenticationService(pool, configuration)
	if err != nil {
		t.Fatal("service composition failed", err)
	}
	secret, _ := primitive.NewSecret([]byte("synthetic-test-password"))
	defer secret.Destroy()
	caller := authorization.DecisionContext{Request: authorization.Request{Subject: authorization.Subject{ID: "AAAAAAAAAAAAAAAAAAAAAg", Kind: authorization.SubjectUser}}}
	request := passworddb.ReauthenticationRequest{TenantID: "AAAAAAAAAAAAAAAAAAAAAQ", Session: auth.NewBearerCredential(wire), Password: secret, Target: configuration.Targets[0], Caller: caller, Network: "192.0.2.1", Device: "device"}
	workflow, err := passworddb.NewVerificationWorkflow(service)
	if err != nil {
		t.Fatal("portable native composition failed", err)
	}
	// The legacy direct API derives policy context. Portable transport callers
	// provide complete trusted context without changing legacy callers below.
	portableCaller := caller.Clone()
	portableCaller.PolicyRevision = 9
	portableCaller.Request.Tenant = authorization.TenantID(request.TenantID)
	portableCaller.Request.Action = "identity.password.verify"
	portableCaller.Request.Resource = authorization.Resource{Type: "identity.request-admission", ID: "identity.password.verify"}
	result := testBearerPasswordVerificationHTTP(t, ctx, pool, configuration, workflow, request)
	if result.Proof.SessionID != s.SessionID || result.Proof.SessionVersion != s.Version || result.Proof.Proof.Subject != string(s.UserID) || result.Proof.Proof.Tenant != string(s.TenantID) || result.Proof.Proof.Method != "password" || result.Proof.Proof.Purpose != request.Target.Purpose || result.Proof.Action != request.Target.Action || result.Proof.Proof.Audience != request.Target.Audience {
		t.Fatal("proof lost source/target scope")
	}
	repository, _ := passworddb.NewRepository(pool, configuration.Repository)
	stored, err := repository.Reauthentication(ctx, result.Proof.Proof.ID)
	if err != nil {
		t.Fatal(err)
	}
	frame, _ := stored.SigningBytes()
	if !ed25519.Verify(public, frame, stored.Signature) || stored.Proof != result.Proof {
		t.Fatal("native signed original changed")
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(result.CommandID))
	var records, audits, events int
	if err = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, raw).Scan(&records, &audits, &events); err != nil || records != 1 || audits != 1 || events != 1 {
		t.Fatal("effects not committed together", err)
	}
	sessions, _ := sessionpg.NewRepository(pool, configuration.Session)
	unchanged, err := sessions.Get(ctx, s.TenantID, s.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	beforeFields, beforeErr := sessionpg.OriginalSessionFields(original)
	afterFields, afterErr := sessionpg.OriginalSessionFields(unchanged.Session)
	if beforeErr != nil || afterErr != nil || !reflect.DeepEqual(beforeFields, afterFields) {
		t.Fatal("verification extended or changed source session")
	}
	recovered, err := workflow.Recover(ctx, identity.RecoveryQuery{CommandID: result.CommandID, TenantID: s.TenantID, UserID: s.UserID, ActorID: identity.ActorID(s.UserID), ActorKind: authorization.SubjectUser, OperationID: "identity.password.verify", RecordID: string(result.CommandID)}, portableCaller)
	if err != nil || recovered.Outcome != identity.CommitOutcomeCommitted || recovered.Proof != (auth.ReauthenticationProof{}) {
		t.Fatal("recovery reissued proof or lost outcome", err)
	}
	// Independent invocations own distinct command IDs, not a caller-selected
	// replay key. They share the immutable session, not a Secret owner: the
	// primitive deliberately rejects simultaneous borrowing of one owner.
	t.Run("concurrent-independent-proofs", func(t *testing.T) {
		const count = 4
		var results [count]passworddb.ReauthenticationResult
		var failures [count]error
		var group sync.WaitGroup
		for i := range count {
			candidate, e := primitive.NewSecret([]byte("synthetic-test-password"))
			if e != nil {
				t.Fatal("independent secret unavailable")
			}
			r := request
			r.Password = candidate
			group.Go(func() {
				defer candidate.Destroy()
				results[i], failures[i] = service.Verify(ctx, r)
			})
		}
		group.Wait()
		seen := make(map[identity.CommandID]bool)
		for i, r := range results {
			if failures[i] != nil || r.Outcome != identity.CommitOutcomeCommitted || r.Proof.Proof.ID == "" || seen[r.CommandID] {
				t.Fatal("concurrent invocation lost distinct committed proof", failures[i])
			}
			seen[r.CommandID] = true
		}
	})
	// Fail the real native effect tables, not a substituted coordinator. An
	// already charged abuse attempt survives; protected proof/audit/outbox rows
	// must all roll back even when a later participant fails.
	for _, table := range []string{"audit.identity_command_bindings", "public.identity_outbox_bindings"} {
		t.Run("rollback-"+table, func(t *testing.T) {
			if _, e := pool.Raw().Exec(ctx, `CREATE FUNCTION identity_password.reject_test_effect() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic effect failure'; END $$`); e != nil {
				t.Fatal("rollback fixture function failed")
			}
			t.Cleanup(func() {
				if _, e := pool.Raw().Exec(ctx, `DROP TRIGGER reject_test_effect ON `+table+`; DROP FUNCTION identity_password.reject_test_effect()`); e != nil {
					t.Error("rollback fixture cleanup failed")
				}
			})
			if _, e := pool.Raw().Exec(ctx, `CREATE TRIGGER reject_test_effect BEFORE INSERT ON `+table+` FOR EACH ROW EXECUTE FUNCTION identity_password.reject_test_effect()`); e != nil {
				t.Fatal("rollback fixture trigger failed")
			}
			before := riskFixture.charges.Load()
			failed, e := service.Verify(ctx, request)
			wantOutcome, wantAudits := identity.CommitOutcomeNotCommitted, 1
			if table == "audit.identity_command_bindings" {
				// The same outage also prevents the mandatory terminal failure
				// audit: rollback alone cannot certify the durable outcome.
				wantOutcome, wantAudits = identity.CommitOutcomeUnknown, 0
			}
			if e == nil || failed.Proof != (auth.ReauthenticationProof{}) || failed.Outcome != wantOutcome || riskFixture.charges.Load() != before+1 {
				t.Fatal("failed participant delivered proof or lost known rollback", e, failed.Outcome)
			}
			command, e := base64.RawURLEncoding.DecodeString(string(failed.CommandID))
			if e != nil || len(command) != 16 {
				t.Fatal("rollback lost original command identity")
			}
			var records, audits, events int
			if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, command).Scan(&records, &audits, &events); e != nil || records != 0 || audits != wantAudits || events != 0 {
				t.Fatal("failed participant left partial protected effects")
			}
		})
	}
	t.Run("deadline-during-material-lock", func(t *testing.T) {
		tx, e := pool.Raw().Begin(ctx)
		if e != nil {
			t.Fatal("lock fixture could not begin")
		}
		defer func() {
			if e := tx.Rollback(ctx); e != nil {
				t.Error("lock fixture cleanup failed")
			}
		}()
		if _, e = tx.Exec(ctx, `SELECT credential_id FROM identity_password.credentials WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ' FOR UPDATE`); e != nil {
			t.Fatal("lock fixture could not acquire owner lock")
		}
		bounded, stop := context.WithTimeout(ctx, 150*time.Millisecond)
		defer stop()
		before := riskFixture.charges.Load()
		failed, e := service.Verify(bounded, request)
		if !errors.Is(e, context.DeadlineExceeded) || failed.Proof != (auth.ReauthenticationProof{}) || failed.Outcome == identity.CommitOutcomeCommitted || riskFixture.charges.Load() != before+1 {
			t.Fatal("lock wait lost caller deadline or delivered authority", e, failed.Outcome)
		}
	})
	t.Run("restart-recovery-does-not-need-password-or-source-session", func(t *testing.T) {
		if _, e := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET state='revoked'`); e != nil {
			t.Fatal("restart fixture could not revoke source")
		}
		t.Cleanup(func() {
			if _, e := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET state='active'`); e != nil {
				t.Error("restart fixture cleanup failed")
			}
		})
		restarted, e := passworddb.NewReauthenticationService(pool, configuration)
		if e != nil {
			t.Fatal("restart composition failed")
		}
		before := riskFixture.charges.Load()
		got, e := restarted.Recover(ctx, s.TenantID, result.CommandID, caller)
		if e != nil || got.Outcome != identity.CommitOutcomeCommitted || got.CommandID != result.CommandID || got.Proof != (auth.ReauthenticationProof{}) || riskFixture.charges.Load() != before {
			t.Fatal("restart recovery renewed authentication or lost original outcome", e)
		}
	})
	for _, before := range []bool{true, false} {
		name := "disconnect-after-commit"
		if before {
			name = "disconnect-before-commit"
		}
		t.Run(name, func(t *testing.T) {
			fault := &reauthenticationCommitFault{before: before}
			faultPool, e := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if e != nil {
				t.Fatal("fault pool unavailable")
			}
			t.Cleanup(func() {
				cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if e := faultPool.Close(cleanup); e != nil {
					t.Error("fault pool cleanup failed")
				}
			})
			c := configuration
			c.Coordinator.LeaseDuration = 500 * time.Millisecond
			faultService, e := passworddb.NewReauthenticationService(faultPool, c)
			if e != nil {
				t.Fatal("fault service composition failed")
			}
			original, e := faultService.Verify(ctx, request)
			if e == nil || !fault.hit.Load() || original.Outcome != identity.CommitOutcomeUnknown || original.Proof != (auth.ReauthenticationProof{}) || original.CommandID == "" {
				t.Fatal("disconnect fabricated outcome or delivered proof", e, original.Outcome)
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(original.CommandID))
			var records, audits, events int
			if e := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.reauthentication_records WHERE command_id=$1),(SELECT count(*) FROM audit.identity_command_bindings WHERE command_id=$1),(SELECT count(*) FROM public.identity_outbox_bindings WHERE command_id=$1)`, id).Scan(&records, &audits, &events); e != nil {
				t.Fatal("independent original state read failed")
			}
			want, outcome := 1, identity.CommitOutcomeCommitted
			if before {
				want, outcome = 0, identity.CommitOutcomeNotCommitted
			}
			if records != want || audits != want || events != want {
				t.Fatal("disconnect did not preserve all-or-none server effects")
			}
			// Restart over an unfaulted primary pool. Before-COMMIT absence
			// becomes terminal only after the original reservation lease ends.
			restarted, e := passworddb.NewReauthenticationService(pool, c)
			if e != nil {
				t.Fatal("recovery restart failed")
			}
			bounded, stop := context.WithTimeout(ctx, 3*time.Second)
			defer stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			charges := riskFixture.charges.Load()
			for {
				recovered, e := restarted.Recover(bounded, s.TenantID, original.CommandID, caller)
				if recovered.Proof != (auth.ReauthenticationProof{}) || riskFixture.charges.Load() != charges {
					t.Fatal("disconnect recovery renewed authority or charged again")
				}
				if recovered.Outcome == outcome {
					if !before && e != nil {
						t.Fatal("committed recovery failed", e)
					}
					break
				}
				select {
				case <-bounded.Done():
					t.Fatal("original disconnect outcome remained unresolved", e, recovered.Outcome)
				case <-ticker.C:
				}
			}
		})
	}
	for _, state := range []struct{ name, mutate, restore string }{
		{"global-epoch", `UPDATE identity.global_authorities SET version=2`, `UPDATE identity.global_authorities SET version=1`},
		{"tenant-epoch", `UPDATE identity.tenant_authorities SET version=2`, `UPDATE identity.tenant_authorities SET version=1`},
		{"disabled-tenant", `UPDATE identity.tenant_authorities SET enabled=false`, `UPDATE identity.tenant_authorities SET enabled=true`},
		{"user-epoch", `UPDATE identity.users SET authority_version=4 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`, `UPDATE identity.users SET authority_version=3 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`},
		{"identifier-epoch", `UPDATE identity.users SET identifier_version=5 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`, `UPDATE identity.users SET identifier_version=4 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`},
		{"credential-epoch", `UPDATE identity.users SET credential_version=6 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`, `UPDATE identity.users SET credential_version=5 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`},
		{"authorization-epoch", `UPDATE authorization_subject_authorities SET version=9 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`, `UPDATE authorization_subject_authorities SET version=8 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`},
		{"family-epoch", `UPDATE reauth_sessions.families SET version=2`, `UPDATE reauth_sessions.families SET version=1`},
		{"revoked-family", `UPDATE reauth_sessions.families SET state='revoked'`, `UPDATE reauth_sessions.families SET state='active'`},
	} {
		t.Run(state.name, func(t *testing.T) {
			if _, e := pool.Raw().Exec(ctx, state.mutate); e != nil {
				t.Fatal("owner-change fixture failed")
			}
			t.Cleanup(func() {
				if _, e := pool.Raw().Exec(ctx, state.restore); e != nil {
					t.Error("owner-change fixture cleanup failed")
				}
			})
			got, _ := service.Verify(ctx, request)
			if got.Proof != (auth.ReauthenticationProof{}) || got.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("stale source owner issued authority")
			}
			id, _ := base64.RawURLEncoding.DecodeString(string(got.CommandID))
			var count int
			if e := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_password.reauthentication_records WHERE command_id=$1`, id).Scan(&count); e != nil || count != 0 {
				t.Fatal("stale owner left durable proof")
			}
		})
	}
	t.Run("expired-source-session", func(t *testing.T) {
		c := configuration
		c.Verifier.Now = func() time.Time { return now.Add(31 * time.Minute) }
		expired, e := passworddb.NewReauthenticationService(pool, c)
		if e != nil {
			t.Fatal("expired-source composition failed")
		}
		before := riskFixture.charges.Load()
		got, e := expired.Verify(ctx, request)
		if e == nil || got.Proof != (auth.ReauthenticationProof{}) || got.Outcome == identity.CommitOutcomeCommitted || riskFixture.charges.Load() != before {
			t.Fatal("expired original session reached password work or gained authority")
		}
	})
	for _, kind := range []string{"wrong-password", "throttle", "counter-outage", "blocked", "changed-reference", "revoked-session", "foreign-target", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			r := request
			cleanup := func() {}
			call := ctx
			switch kind {
			case "wrong-password":
				wrong, _ := primitive.NewSecret([]byte("incorrect"))
				r.Password = wrong
				cleanup = wrong.Destroy
			case "throttle":
				riskFixture.throttle.Store(true)
				cleanup = func() { riskFixture.throttle.Store(false) }
			case "counter-outage":
				riskFixture.outage.Store(true)
				cleanup = func() { riskFixture.outage.Store(false) }
			case "blocked":
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='banned' WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`); e != nil {
					t.Fatal(e)
				}
				cleanup = func() {
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='active' WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`); e != nil {
						t.Error("blocked fixture cleanup failed")
					}
				}
			case "changed-reference":
				if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET version=8 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ';UPDATE identity_password.credentials SET version=8 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`); e != nil {
					t.Fatal(e)
				}
				cleanup = func() {
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET version=7 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ';UPDATE identity_password.credentials SET version=7 WHERE tenant_id='AAAAAAAAAAAAAAAAAAAAAQ'`); e != nil {
						t.Error("credential fixture cleanup failed")
					}
				}
			case "revoked-session":
				if _, e := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET state='revoked'`); e != nil {
					t.Fatal(e)
				}
				cleanup = func() {
					if _, e := pool.Raw().Exec(ctx, `UPDATE reauth_sessions.sessions SET state='active'`); e != nil {
						t.Error("session fixture cleanup failed")
					}
				}
			case "foreign-target":
				r.Target.Audience = "foreign"
			case "cancelled":
				var stop context.CancelFunc
				call, stop = context.WithCancel(ctx)
				stop()
			}
			defer cleanup()
			before := riskFixture.charges.Load()
			denied, e := service.Verify(call, r)
			if denied.Proof != (auth.ReauthenticationProof{}) || denied.Outcome == identity.CommitOutcomeCommitted {
				t.Fatal("denied submission delivered authority")
			}
			if kind == "wrong-password" || kind == "blocked" || kind == "changed-reference" {
				if e != nil || riskFixture.charges.Load() != before+1 {
					t.Fatal("neutral failure was uncharged or exposed", e)
				}
			}
			if kind == "cancelled" && !errors.Is(e, context.Canceled) {
				t.Fatal("cancellation classification lost", e)
			}
		})
	}
	t.Run("native-password-change", func(t *testing.T) { testNativePasswordChange(t, ctx, pool, configuration, service, request) })
}
