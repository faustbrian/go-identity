//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	authoritypg "github.com/faustbrian/go-authorization/postgres"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	primitive "github.com/faustbrian/go-password"
	database "github.com/faustbrian/go-postgres"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/v2/postgres/identity"
	"github.com/jackc/pgx/v5"
)

// External risk counting/audit are deliberate doubles. Password comparison and
// kernel, credential, pre-auth, session, security audit and outbox SQL are real.
type signinRiskBoundary struct{}

// Exercise expiry inside actual required audit persistence, not before the
// feature mutation. The real owner still writes every native audit slot.
type signinDelayedAudit struct {
	*auditpg.IdentityContributor
	until time.Time
}

func (a *signinDelayedAudit) PersistAudits(ctx context.Context, w kernel.Work) error {
	if err := a.IdentityContributor.PersistAudits(ctx, w); err != nil {
		return err
	}
	timer := time.NewTimer(max(time.Until(a.until), 0))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

const signinTestTenant = "AAAAAAAAAAAAAAAAAAAAAQ"
const signinTestUser = "AAAAAAAAAAAAAAAAAAAAAg"
const signinTestActor = "AAAAAAAAAAAAAAAAAAAAAw"

func (signinRiskBoundary) Mutate(_ context.Context, c risk.CounterCommand) (risk.CounterResult, error) {
	b := c.Bindings()
	var counters []risk.Counter
	for _, target := range b.Targets {
		counters = append(counters, risk.Counter{Kind: string(target.Dimension), Value: 1, ObservedAt: b.PreparedAt, WindowStartedAt: b.PreparedAt, WindowExpiresAt: b.PreparedAt.Add(b.Window)})
	}
	return risk.NewCounterResult(c, risk.CounterCommitted, counters)
}
func (signinRiskBoundary) Append(_ context.Context, r audit.Record) (audit.AppendResult, error) {
	return audit.AppendResult{RecordID: r.ID(), Status: audit.AppendAccepted}, nil
}
func (signinRiskBoundary) AppendBatch(context.Context, []audit.Record) (audit.BatchResult, error) {
	return audit.BatchResult{}, errors.New("unexpected batch")
}

func signinTestAdmission(t *testing.T, ctx context.Context, b identity.CommandBinding) risk.AuthenticationAdmission {
	t.Helper()
	policy, err := risk.NewPolicy(risk.PolicyConfig{Version: 3, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"status", "velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"status", "velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{71}, 32))
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: policy, Store: signinRiskBoundary{}, Clock: time.Now, Timeout: time.Second, Keys: []risk.CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	policyID, _ := identity.NewCommandID()
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: time.Second, Counters: &counters, Sources: []risk.Source{{Name: "status", Version: "signin-test-v1", Timeout: time.Second, Read: func(_ context.Context, c risk.Context) (risk.Signal, error) {
		return risk.Signal{Tenant: c.Tenant, Operation: c.Operation, Attempt: c.Attempt, Name: "status", State: risk.SignalClean, Trust: risk.ServerVerified, ObservedAt: c.Now, ExpiresAt: c.Now.Add(30 * time.Second)}, nil
	}}}, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(policyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: signinRiskBoundary{}, Mode: audit.DeliveryFailClosed}, OnLoss: func(context.Context, risk.DecisionDelivery) error { return nil }}})
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{72}, 32), bytes.Repeat([]byte{73}, 32))
	custody, err := risk.NewAuthenticationAdmissionCustody(risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "signin-test-v1", Keys: []risk.EvidenceKey{evidence}})
	if err != nil {
		t.Fatal(err)
	}
	scope := risk.Context{Tenant: string(b.TenantID), Operation: risk.Action(b.OperationID), Attempt: string(b.CommandID)}
	subject := risk.Subject{Network: "192.0.2.1", Device: "synthetic-device", IdentifierDigest: strings.Repeat("a", 64)}
	// Before comparison there is no verified human actor. The later command
	// audit separately retains its trusted ingress workload under the same ID.
	result, err := evaluator.Evaluate(ctx, risk.EvaluateRequest{Context: scope, Phase: risk.NonIssuing, Subject: subject, Attribution: &risk.DecisionAttribution{CommandID: b.CommandID, CorrelationID: b.CommandID, Actor: audit.ActorInput{Kind: audit.ActorAnonymous}, Subject: identity.SecurityAuthenticationAttempt, SubjectID: string(b.CommandID)}})
	if err != nil {
		// EvaluateError retains only the owner's stable redacted classification,
		// never an external counter/source diagnostic or trusted input values.
		t.Fatal("risk evaluation failed", errors.Unwrap(err))
	}
	admission, err := custody.Prepare(ctx, result, scope, subject)
	if err != nil {
		t.Fatal("risk custody failed", err)
	}
	return admission
}

// This fixture writer seeds a test-owned original flow. Production initiation
// instead supplies the sole coordinator Work, never this autocommit fixture.
type signinTestTx struct{ pool *database.Pool }

func (t signinTestTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return t.pool.Raw().Query(ctx, sql, args...)
}

func (t signinTestTx) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	tag, err := t.pool.Raw().Exec(ctx, sql, args...)
	return tag.RowsAffected(), err
}

func TestNativeSigninPhaseIntegration(t *testing.T) {
	port, file := os.Getenv("IDENTITY_REFERENCE_POSTGRES_PORT"), os.Getenv("IDENTITY_REFERENCE_PASSWORD_FILE")
	material, err := os.ReadFile(file)
	if err != nil || port == "" {
		t.Fatal("disposable primary required")
	}
	dsn := (&url.URL{Scheme: "postgres", User: url.UserPassword("postgres", strings.TrimSpace(string(material))), Host: net.JoinHostPort("127.0.0.1", port), Path: "/identity_test", RawQuery: "sslmode=disable"}).String()
	clear(material)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4})
	if err != nil {
		t.Fatal("primary unavailable")
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if pool.Close(stop) != nil {
			t.Error("pool cleanup")
		}
	}()
	base := kernel.CredentialReplacementMigrationSource{Base: kernel.CredentialMigrationSource{Base: kernel.StatusMigrationSource{Base: kernel.MigrationSource{}, Version: 10}, Version: 11}, Version: 12}
	sessionConfig := sessionpg.Config{Schema: "signin_sessions", MaximumDuration: time.Second}
	for _, source := range []migrations.Source{
		kernel.DirectoryAuthorityMigrationSource{Base: base, Version: 13, GlobalAuthorityID: "signin-deployment", TenantIDs: []identity.TenantID{signinTestTenant}},
		MigrationSource{},
		sessionpg.IssueMigrationSource{Base: sessionpg.RevocationMigrationSource{Base: sessionpg.MigrationSource{Schema: sessionConfig.Schema, Version: 1}, Version: 2}, Version: 3},
		sessionpg.PreAuthMigrationSource{Schema: sessionConfig.Schema, Version: 4},
		sessionpg.PreAuthReleaseMigrationSource{Schema: sessionConfig.Schema, Version: 5},
		sessionpg.CSRFMigrationSource{Schema: sessionConfig.Schema, Version: 6},
		sessionpg.OTPIssueMigrationSource{Schema: sessionConfig.Schema, Version: 7},
		sessionpg.PasswordSigninMigrationSource{Schema: sessionConfig.Schema, Version: 8},
	} {
		history, e := source.Load(ctx)
		if e != nil {
			t.Fatal("migration source", e)
		}
		for _, m := range history {
			if _, e = pool.Raw().Exec(ctx, m.UpSQL()); e != nil {
				t.Fatal("migration execution", e)
			}
		}
	}
	if _, err = pool.Raw().Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
		t.Fatal("audit install", err)
	}
	for _, source := range []fs.FS{auditpg.Migrations(), outboxpg.Migrations(), lifecyclepg.Migrations()} {
		files, e := fs.ReadDir(source, ".")
		if e != nil {
			t.Fatal(e)
		}
		for _, file := range files {
			wire, e := fs.ReadFile(source, file.Name())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); e != nil {
				t.Fatal("effect install", e)
			}
		}
	}
	am, err := authoritypg.AuthoritySchemaMigration(300)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Raw().Exec(ctx, am.Up); err != nil {
		t.Fatal("authorization install", err)
	}
	limits := primitive.Limits{PasswordBytes: 128, EncodedHashBytes: 256, Argon2Time: 2, MemoryKiB: 16, Parallelism: 1, SaltBytes: 16, OutputBytes: 32, BcryptCost: 4, Concurrent: 2, Queue: 2}
	policy, err := primitive.NewPolicy(primitive.PolicyConfig{Algorithm: primitive.Argon2id, Argon2id: primitive.Argon2idParameters{Version: 19, Time: 1, MemoryKiB: 8, Parallelism: 1, SaltLength: 8, OutputLength: 16}, Limits: limits})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := primitive.New(policy)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := crypto.Hash(ctx, []byte(" synthetic-password "))
	if err != nil {
		t.Fatal("synthetic hashing")
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','active',1);
INSERT INTO identity.credential_references(tenant_id,user_id,credential_id,kind,owner,version,enabled) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','password',1,'identity/password',7,true);
INSERT INTO identity.identifiers(tenant_id,user_id,identifier_id,kind,canonical_value,verified,is_primary,version,verification_state,verification_version,verified_at) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','email','email','person@example.test',true,true,1,2,1,clock_timestamp());
INSERT INTO authorization_subject_authorities VALUES('AAAAAAAAAAAAAAAAAAAAAQ','users','AAAAAAAAAAAAAAAAAAAAAg',1)`); err != nil {
		t.Fatal("authority fixtures", err)
	}
	if _, err = pool.Raw().Exec(ctx, `INSERT INTO identity_password.credentials(tenant_id,user_id,credential_id,version,algorithm,encoded_hash) VALUES('AAAAAAAAAAAAAAAAAAAAAQ','AAAAAAAAAAAAAAAAAAAAAg','password',7,'argon2id',$1)`, hash.String()); err != nil {
		t.Fatal("synthetic material")
	}
	repository, err := NewRepository(pool, Config{MaximumDuration: time.Second, HashPolicy: policy})
	if err != nil {
		t.Fatal(err)
	}
	domain, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	audits, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	outbox, err := lifecyclepg.NewContributor()
	if err != nil {
		t.Fatal(err)
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "signin-deployment", PolicyNamespace: "users", Audience: "backend", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	effect, err := sessionpg.NewPasswordSigninEffect(sessionConfig, profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"commit", "rollback", "stale-credential", "expired-delivery", "expired-audit"} {
		t.Run(mode, func(t *testing.T) {
			r, _, flowKey, _ := nativeSigninFlow(t)
			r.Device = "synthetic-device"
			r.TenantID = signinTestTenant
			r.Caller.Request.Tenant = signinTestTenant
			r.Caller.Request.Subject.ID = signinTestActor
			flowID, _ := identity.NewPreAuthTransactionID()
			r.PreAuthID = flowID
			now := time.Now().UTC().Truncate(time.Microsecond)
			flowBinding := session.PreAuthBinding{ID: flowID, Intent: session.PreAuthIntent{TenantID: r.TenantID, Action: "identity.password.signin", Origin: r.Origin, CallbackURL: r.CallbackURL, Nonce: [32]byte{1}, Remember: r.Remember, PolicyID: "login", PolicyVersion: 3}, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
			cookie, _ := session.ParseToken(r.Cookie.Token())
			digest, e := cookie.PreAuthDigest(flowKey, flowBinding)
			if e != nil {
				t.Fatal(e)
			}
			flow, e := session.NewPreAuthTransaction(session.PreAuthTransactionSpec{Binding: flowBinding, Cookie: digest, Version: 1})
			if e != nil {
				t.Fatal(e)
			}
			if e = sessionpg.InsertPreAuth(ctx, signinTestTx{pool}, sessionConfig, flow); e != nil {
				t.Fatal("preauth insert", e)
			}
			id, _ := identity.NewCommandID()
			op := identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.signin", SchemaID: "password-signin", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordOmitted}
			b := identity.CommandBinding{CommandID: id, TenantID: r.TenantID, AnonymousFlowID: string(flowID), ActorID: signinTestActor, ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "login", PolicyVersion: 3, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: string(id)}
			admission := signinTestAdmission(t, ctx, b)
			observation := &reauthenticationObservation{repository: repository}
			verifier, e := password.NewPasswordVerifier(password.VerifierConfig{Primitive: crypto, Repository: observation, MaximumBytes: 128, Timeout: time.Second, DummyHash: hash, Now: time.Now})
			if e != nil {
				t.Fatal(e)
			}
			comparison, e := verifier.VerifyPassword(ctx, password.VerifyPasswordRequest{TenantID: r.TenantID, SubjectID: signinTestUser, Password: r.Password})
			if e != nil || !comparison.Matched {
				t.Fatal("real comparison failed")
			}
			recipient, e := domain.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: r.TenantID, Kind: identity.IdentifierEmail, CanonicalValue: "person@example.test", Eligibility: kernel.RecipientVerified})
			if e != nil || recipient.Suppressed {
				t.Fatal("real recipient failed", e)
			}
			signer, e := NewSigninSigningKey("signin-key", ed25519.NewKeyFromSeed(bytes.Repeat([]byte{74}, 32)))
			if e != nil {
				t.Fatal(e)
			}
			keyID, public := signer.public()
			proofUntil := now.Add(time.Minute)
			if mode == "expired-audit" {
				proofUntil = now.Add(time.Second)
			}
			signed, e := signer.sign(auth.SignedSignInRecord{Issuer: "issuer", Environment: "test", State: auth.SignInStateAuthenticated, ProofVersion: 1, CredentialID: "password", CredentialVersion: comparison.CredentialVersion, Proof: auth.Proof{ID: auth.ProofID(id), Tenant: signinTestTenant, Subject: signinTestUser, Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "backend", IssuedAt: now, ExpiresAt: proofUntil}})
			if e != nil {
				t.Fatal(e)
			}
			keys, _ := kernel.KernelAuthorityKeys(kernel.DirectoryAuthorityQuery{GlobalAuthorityID: profile.GlobalAuthorityID, TenantID: r.TenantID}, signinTestUser)
			sessionID, familyID := "signin-session-"+mode, "signin-family-"+mode
			skeys, _ := sessionpg.SessionAuthorityKeys(r.TenantID, signinTestUser, familyID, sessionID)
			pkey, _ := (authoritypg.AuthorityScope{TenantID: signinTestTenant, SubjectID: signinTestUser, PolicyNamespace: "users"}).Key()
			binding := func(k string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: k, Version: 1} }
			authority, e := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: binding(keys.Global), Tenant: binding(keys.Tenant), User: binding(keys.User), Identifier: binding(keys.Identifier), Credential: binding(keys.Credential), SessionFamily: binding(skeys.Family), Session: binding(skeys.Session), Authorization: binding(pkey)})
			if e != nil {
				t.Fatal(e)
			}
			lookupKey, _ := session.NewDigestKey(1, bytes.Repeat([]byte{75}, 32))
			executor := &signinExecution{clock: signinTestClock{}}
			cookiePolicy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
			csrfKey, _ := session.NewCSRFKey(1, bytes.Repeat([]byte{76}, 32))
			issuer, e := session.NewPasswordSessionIssuerWithCSRF(executor, session.IssuerConfig{Clock: signinTestClock{}, MaximumDuration: 2 * time.Second, LookupKey: lookupKey, TokenSize: 32, Cookie: cookiePolicy}, csrfKey)
			if e != nil {
				t.Fatal("native issuer", e)
			}
			prepared, e := issuer.PreparePassword(b, session.SessionSpec{TenantID: signinTestTenant, UserID: signinTestUser, SessionID: sessionID, FamilyID: familyID, Audience: "backend", Version: 1, FamilyVersion: 1, Remember: r.Remember, Authority: authority, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: signed.Proof, ProofVersion: 1, CredentialID: "password", CredentialVersion: 7}, IssuedAt: now, LastActivityAt: now})
			if e != nil {
				t.Fatal(e)
			}
			record, ok := prepared.Session()
			if !ok {
				t.Fatal("prepared native session missing")
			}
			fields, e := sessionpg.PasswordSigninSessionFields(record)
			if e != nil {
				t.Fatal(e)
			}
			command, e := identity.NewFeaturePasswordSigninCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, r.Password, r.Cookie)
			if e != nil {
				t.Fatal(e)
			}
			prepared, e = issuer.BindPassword(prepared, command)
			if e != nil {
				t.Fatal("bind original", e)
			}
			phase := &signinPhase{operation: op, expected: command, effect: effect, recipient: recipient, material: observation.last, request: r, flow: flow, flowKey: flowKey, record: signed, verificationKeys: map[string]ed25519.PublicKey{keyID: public}, admission: admission, maximumHashBytes: 256}
			var auditing kernel.Contributor = audits
			if mode == "expired-audit" {
				auditing = &signinDelayedAudit{IdentityContributor: audits, until: proofUntil.Add(time.Millisecond)}
			}
			registry, e := kernel.NewContributorRegistry([]kernel.Contributor{domain, auditing, outbox, phase})
			if e != nil {
				t.Fatal(e)
			}
			coordinator, e := kernel.NewCoordinator(pool, registry, kernel.CoordinatorConfig{MaximumDuration: 2 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {1}}})
			if e != nil {
				t.Fatal(e)
			}
			plan, e := signinPlan(coordinator, registry, phase, command, now)
			if e != nil {
				t.Fatal("plan", e)
			}
			if mode == "stale-credential" {
				if _, e = pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=false WHERE tenant_id=$1`, signinTestTenant); e != nil {
					t.Fatal(e)
				}
				defer func() {
					if _, e := pool.Raw().Exec(ctx, `UPDATE identity.credential_references SET enabled=true WHERE tenant_id=$1`, signinTestTenant); e != nil {
						t.Error("restore fixture")
					}
				}()
			}
			executor.coordinator, executor.phase, executor.plan, executor.record = coordinator, phase, plan, record
			if mode == "expired-delivery" {
				executor.clock = signinFixedClock{signed.Proof.ExpiresAt}
				issued, issueErr := issuer.Issue(ctx, prepared)
				if issueErr == nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Token != (session.Token{}) || issued.Cookie.Name != "" || issued.Session == (session.Session{}) {
					t.Fatal("expired delivery lost commit or disclosed bearer")
				}
				if _, csrfErr := prepared.CSRFToken(); csrfErr == nil {
					t.Fatal("expired delivery disclosed synchronizer")
				}
			} else if mode == "stale-credential" || mode == "expired-audit" {
				issued, issueErr := issuer.Issue(ctx, prepared)
				if issueErr == nil || issued.CommitOutcome != identity.CommitOutcomeNotCommitted || issued.Token != (session.Token{}) || issued.Session != (session.Session{}) || issued.Cookie.Name != "" {
					t.Fatal("invalidated admission did not roll back native issuance")
				}
				if _, csrfErr := prepared.CSRFToken(); csrfErr == nil {
					t.Fatal("stale credential disclosed synchronizer")
				}
			} else if mode == "commit" {
				issued, issueErr := issuer.Issue(ctx, prepared)
				if issueErr != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted || issued.Replayed || issued.Token == (session.Token{}) || issued.Cookie.Name != "__Host-session" || issued.Cookie.Value != "" {
					t.Fatal("new commit did not grant original delivery", issueErr)
				}
				csrf, csrfErr := prepared.CSRFToken()
				wire, revealErr := csrf.Reveal()
				if csrfErr != nil || revealErr != nil || wire == "" || record.CSRFState().Check(session.CSRFBinding{TenantID: r.TenantID, SessionID: sessionID, SessionVersion: 1}, csrf, csrfKey) != nil {
					t.Fatal("committed synchronizer delivery")
				}
				if _, secondErr := csrf.Reveal(); secondErr == nil {
					t.Fatal("synchronizer revealed twice")
				}
				if _, revealErr = issued.Token.Reveal(); revealErr != nil {
					t.Fatal("committed original bearer withheld")
				}
				again, secondErr := issuer.Issue(ctx, prepared)
				if secondErr == nil || again.Token != (session.Token{}) {
					t.Fatal("original preparation executed twice")
				}
			} else {
				reservation, _, e := coordinator.ReserveCommand(ctx, b, command, plan)
				if e != nil {
					t.Fatal("reservation", e)
				}
				work, e := coordinator.Begin(ctx, reservation)
				if e != nil {
					t.Fatal(e)
				}
				defer coordinator.Abort(work, identity.UnavailableError{})
				receipt, e := coordinator.ApplyFeature(ctx, work, command)
				if e != nil {
					t.Fatal("rollback setup could not apply", e)
				}
				receipt, e = coordinator.Abort(work, identity.ForbiddenError{})
				if receipt.Outcome != identity.CommitOutcomeNotCommitted {
					t.Fatal("rollback outcome", e)
				}
				if _, csrfErr := prepared.CSRFToken(); csrfErr == nil {
					t.Fatal("rollback disclosed synchronizer")
				}
			}
			var originals, sessions, issuances int
			if e = pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity_password.signin_records WHERE proof_id=$1),(SELECT count(*) FROM signin_sessions.sessions WHERE session_id=$2),(SELECT count(*) FROM signin_sessions.session_issuances WHERE session_id=$2)`, string(id), sessionID).Scan(&originals, &sessions, &issuances); e != nil {
				t.Fatal("effect inspection")
			}
			want := 0
			committed := mode == "commit" || mode == "expired-delivery"
			if committed {
				want = 1
			}
			if originals != want || sessions != want || issuances != want {
				t.Fatal("non-atomic original/session effects")
			}
			var state string
			if e = pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(flowID)).Scan(&state); e != nil {
				t.Fatal("flow inspection")
			}
			if committed && state != "consumed" || !committed && state != "issued" {
				t.Fatal("preauth not atomic", state)
			}
			if committed {
				stored, e := repository.SignInAuthentication(ctx, auth.ProofID(id))
				if e != nil || stored.Proof != signed.Proof {
					t.Fatal("committed original source", e)
				}
				frame, _ := stored.SigningBytes()
				if !ed25519.Verify(public, frame, stored.Signature) {
					t.Fatal("original signature")
				}
			}
		})
	}
}

type signinTestClock struct{}

func (signinTestClock) Now() time.Time { return time.Now().UTC() }

type signinFixedClock struct{ now time.Time }

func (c signinFixedClock) Now() time.Time { return c.now }
