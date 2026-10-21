//go:build integration

package anonymouspostgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	auditpg "github.com/faustbrian/go-audit/postgres"
	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
)

type anonymousPolicy struct{}

func (anonymousPolicy) Decide(_ context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	return authorization.Decision{Outcome: authorization.Allow, Revision: c.PolicyRevision}, nil
}

type publicAnonymousFixture struct {
	ctx        context.Context
	pool       *database.Pool
	service    *anonymouspg.SigninService
	config     anonymouspg.SigninConfig
	keys       *keyring.Provider
	fresh      func() anonymous.SigninRequest
	lookupKey  session.DigestKey
	csrfKey    session.CSRFKey
	riskPolicy risk.Policy
	counterKey risk.CounterDigestKey
	evidence   risk.EvidenceKey
}

func newPublicAnonymousFixture(t *testing.T) publicAnonymousFixture {
	t.Helper()
	const tenant = "AAAAAAAAAAAAAAAAAAAAAQ"
	// These fixed roles are created only in the task-owned isolated cluster.
	// Register first so fixture database cleanup runs before role cleanup.
	rolesCreated := false
	t.Cleanup(func() {
		if !rolesCreated {
			return
		}
		ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		connection, err := pgx.Connect(ctx, os.Getenv("IDENTITY_POSTGRES_TEST_DSN"))
		if err != nil {
			t.Error("owned role cleanup connection")
			return
		}
		defer connection.Close(ctx)
		if _, err := connection.Exec(ctx, "DROP ROLE audit_writer,audit_reader,audit_retention"); err != nil {
			t.Error("owned role cleanup", err)
		}
	})
	ctx, pool, _ := nativeFixture(t)
	if _, err := pool.Raw().Exec(ctx, auditpg.FreshInstallPreflightSQL()); err != nil {
		t.Fatal(err)
	}
	rolesCreated = true
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
			if _, err := pool.Raw().Exec(ctx, strings.Split(string(wire), "-- +migrations Down")[0]); err != nil {
				t.Fatal("required effect history", err)
			}
		}
	}
	for _, source := range []migrations.Source{
		kernel.AdmissionPreparationMigrationSource{Base: kernel.PreparationMigrationSource{Base: kernel.RequestKeyPreparationMigrationSource{Base: kernel.RequestKeyMigrationSource{Base: kernel.MigrationSource{}, Version: 50}, Version: 51}, Version: 52}, Version: 53},
		sessionpg.PreAuthMigrationSource{Schema: "session_store", Version: 54},
		riskpg.DurableCounterMigrationSource{Schema: "risk_store", Version: 55},
		sessionpg.PreAuthIssueMigrationSource{Schema: "session_store", Version: 56},
		sessionpg.CSRFMigrationSource{Schema: "session_store", Version: 57},
	} {
		steps, err := source.Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, step := range steps {
			if step.Version() < 50 {
				continue
			}
			if _, err := pool.Raw().Exec(ctx, step.UpSQL()); err != nil {
				t.Fatal("selected public signin history", err)
			}
		}
	}
	riskPolicy, err := risk.NewPolicy(risk.PolicyConfig{Version: 1, Limits: risk.VelocityLimits{MaxDimensions: 4, MaxCounters: 16, MaxWindow: time.Hour, MaxLimit: 120, KeyBytes: 64, RetryAfterMax: time.Hour}, Profiles: []risk.Profile{
		{Class: risk.Authentication, Phase: risk.BeforeCredential, Dimensions: []risk.Dimension{risk.TenantDimension, risk.NetworkDimension, risk.DeviceDimension, risk.IdentifierDimension}, Window: 5 * time.Minute, Limit: 10, ThresholdAction: risk.Throttle, EvidenceTTL: 5 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.CredentialMutation, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectDimension, risk.SessionDimension, risk.NetworkDimension}, Window: 15 * time.Minute, Limit: 5, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.Privileged, Phase: risk.ReserveWithCommand, Dimensions: []risk.Dimension{risk.TenantDimension, risk.ActorDimension, risk.ResourceDimension, risk.NetworkDimension}, Window: time.Hour, Limit: 20, ThresholdAction: risk.Deny, EvidenceTTL: 15 * time.Minute, Unknown: risk.DenyUnknown, MaxCounters: 4, RequiredSignals: []string{"velocity"}},
		{Class: risk.StateNeutralRead, Phase: risk.BeforeReturn, Dimensions: []risk.Dimension{risk.TenantDimension, risk.SubjectOrNetworkDimension}, Window: time.Minute, Limit: 120, ThresholdAction: risk.Throttle, EvidenceTTL: time.Minute, Unknown: risk.StepUpWithIndependentFactor, MaxCounters: 2, RequiredSignals: []string{"velocity"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	counterKey, _ := risk.NewCounterDigestKey(1, bytes.Repeat([]byte{31}, 32))
	store, err := riskpg.NewDurableCounterStore(riskpg.DurableCounterConfig{Pool: pool, Schema: "risk_store", Namespace: "anonymous-native", Policy: riskPolicy, Keys: []risk.CounterDigestKey{counterKey}, ReplayKey: bytes.Repeat([]byte{32}, 32), Tenants: []string{tenant}, MaximumRecords: 1000, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	counters, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: riskPolicy, Store: store, Clock: time.Now, Timeout: time.Second, Keys: []risk.CounterDigestKey{counterKey}})
	if err != nil {
		t.Fatal(err)
	}
	sink, err := auditpg.New(pool.Raw(), auditpg.Config{})
	if err != nil {
		t.Fatal(err)
	}
	riskPolicyID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	evaluator, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: riskPolicy, Counters: &counters, Clock: time.Now, Timeout: 2 * time.Second, DecisionAudit: &risk.DecisionAuditConfig{PolicyID: string(riskPolicyID), Timeout: time.Second, Delivery: audit.RecorderConfig{Sink: sink, Mode: audit.DeliveryFailClosed}, OnLoss: func(ctx context.Context, d risk.DecisionDelivery) error {
		_, err := sink.Append(ctx, d.Record())
		return err
	}}})
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := risk.NewEvidenceKey(1, bytes.Repeat([]byte{33}, 32), bytes.Repeat([]byte{34}, 32))
	query := kernel.CommandQueryPolicy{Authorization: anonymousPolicy{}, Clock: clock.System{}, PolicyVersion: 1}
	requestKeys, err := kernel.NewRequestKeyConfig("anonymous-native", [32]byte{35}, query)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := anonymous.NewPolicy(anonymous.Config{DisplayName: "Guest", PlaceholderEmailDomain: "anonymous.invalid", TTL: 24 * time.Hour, Cleanup: anonymous.CleanupAnonymize})
	if err != nil {
		t.Fatal(err)
	}
	schema := identity.AttributeSchema{ID: "anonymous-profile", Version: 1, Fields: []identity.FieldPolicy{{Name: "name", Kind: identity.AttributeString, Cardinality: identity.CardinalityScalar, Normalization: identity.NormalizeNone, InputPermission: identity.FieldWrite, OutputPermission: identity.FieldRead, WriteAuthorization: identity.FieldWriteSystem, Sensitivity: identity.SensitivityPublic, MigrationVersion: 1}}}
	fields, err := identity.NewAttributeProcessor(schema, anonymousPolicy{}, func(_ context.Context, _ identity.NormalizationPolicy, s identity.AttributeScalar) (identity.AttributeScalar, error) {
		return s, nil
	}, identity.AttributeProcessorConfig{Clock: clock.System{}, MaximumDuration: time.Second, PolicyVersion: 1, ValidateCanonicalUserID: func(_ context.Context, u identity.UserID) error {
		_, err := identity.ParseSubjectID(string(u))
		return err
	}, ValidateValue: func(context.Context, identity.FieldPolicy, identity.AttributeValue) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	flowKey, _ := session.NewDigestKey(1, bytes.Repeat([]byte{36}, 32))
	lookupKey, _ := session.NewDigestKey(1, bytes.Repeat([]byte{37}, 32))
	csrfKey, _ := session.NewCSRFKey(1, bytes.Repeat([]byte{38}, 32))
	cookiePolicy, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-guest", SameSite: http.SameSiteStrictMode})
	keys, _ := keyring.New(map[string][]byte{"anonymous-input": bytes.Repeat([]byte{39}, 32)})
	config := anonymouspg.SigninConfig{Repository: anonymouspg.Config{Schema: "anonymous_store", MaximumDuration: 3 * time.Second}, Sessions: sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}, Profile: sessionpg.AnonymousAdmissionConfig{GlobalAuthorityID: "anonymous-deployment", PolicyNamespace: "guests", Audience: "service-a"}, Policy: policy, ConfigurationID: "anonymous-native-v1", PolicyID: "anonymous-signin", DisplayNameField: "name", Fields: fields, FieldSchema: schema, FlowKeys: []session.DigestKey{flowKey}, Origins: []string{"https://example.test"}, CallbackURLs: []string{""}, RequestKeys: requestKeys, IntentKey: [32]byte{40}, ActiveEnvelopeKeyID: "anonymous-input", Risk: risk.AuthenticationAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: "anonymous-risk-v1", Keys: []risk.EvidenceKey{evidence}}, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 3 * time.Second, LeaseDuration: time.Minute, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: {41}}, QueryPolicy: &query, AdmissionPolicy: &query}, Issuer: session.IssuerConfig{Clock: clock.System{}, MaximumDuration: 2 * time.Second, LookupKey: lookupKey, TokenSize: 32, Cookie: cookiePolicy}, CSRF: csrfKey}
	service, err := anonymouspg.NewSigninService(pool, config, keys)
	if err != nil {
		t.Fatal("native public signin composition", err)
	}
	flowExecutor, err := sessionpg.NewPreAuthIssueExecutor(pool, sessionpg.PreAuthIssueExecutorConfig{Repository: config.Sessions, Coordinator: config.Coordinator, Authorization: anonymousPolicy{}, Clock: clock.System{}, ActorID: "public-ingress", Action: "identity.anonymous.signin", Origin: "https://example.test", PolicyID: config.PolicyID, PolicyVersion: 1, AuditRetentionVersion: 1})
	if err != nil {
		t.Fatal("native preauth executor", err)
	}
	flowCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	flowIssuer, err := session.NewPreAuthIssuer(flowExecutor, session.PreAuthIssuerConfig{ActorID: "public-ingress", Action: "identity.anonymous.signin", Origin: "https://example.test", PolicyID: config.PolicyID, PolicyVersion: 1, Clock: clock.System{}, MaximumDuration: 2 * time.Second, FlowTTL: 5 * time.Minute, LookupKey: flowKey, TokenSize: 32, Cookie: flowCookie})
	if err != nil {
		t.Fatal("native preauth issuer", err)
	}
	fresh := func() anonymous.SigninRequest {
		t.Helper()
		remember, _ := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: 24 * time.Hour, IdleTTL: time.Hour, RefreshAfter: 15 * time.Minute, FreshFor: 15 * time.Minute})
		commandID, _ := identity.NewCommandID()
		prepared, err := flowIssuer.Prepare(session.PreAuthPrepareInput{CommandID: commandID, TenantID: tenant, CorrelationID: string(commandID), Remember: remember})
		if err != nil {
			t.Fatal(err)
		}
		issued, err := flowIssuer.Issue(ctx, prepared)
		if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted {
			t.Fatal("genuine preauth issuance", err)
		}
		flow, err := issued.Flow.Bindings()
		if err != nil {
			t.Fatal(err)
		}
		id := flow.Binding.ID
		wire, err := issued.Token.Reveal()
		if err != nil {
			t.Fatal(err)
		}
		key, _ := identity.NewIdempotencyKey([]byte(id))
		return anonymous.SigninRequest{TenantID: tenant, PreAuthID: id, Cookie: auth.NewBearerCredential(wire), Remember: remember, Origin: "https://example.test", Network: "192.0.2.1", Device: "device", IdempotencyKey: key, Caller: authorization.DecisionContext{PolicyRevision: 1, Request: authorization.Request{Tenant: tenant, Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "public-ingress"}, Action: "identity.anonymous.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.anonymous.signin"}}}}
	}
	return publicAnonymousFixture{ctx: ctx, pool: pool, service: service, config: config, keys: keys, fresh: fresh, lookupKey: lookupKey, csrfKey: csrfKey, riskPolicy: riskPolicy, counterKey: counterKey, evidence: evidence}
}

func TestNativePublicAnonymousSignin(t *testing.T) {
	f := newPublicAnonymousFixture(t)
	ctx, pool, config, keys, fresh, lookupKey := f.ctx, f.pool, f.config, f.keys, f.fresh, f.lookupKey
	var issuer anonymous.Issuer = f.service
	r := fresh()
	result, err := issuer.Signin(ctx, r)
	if err != nil || result.Outcome != identity.CommitOutcomeCommitted || result.Session.Token == (session.Token{}) || result.CSRFToken == (session.CSRFToken{}) || result.Replayed {
		t.Fatal("public anonymous signin did not commit/deliver", err, result.Outcome)
	}
	spec, err := result.Session.Session.Bindings()
	if err != nil || spec.Authentication.Kind != session.AuthenticationAnonymous || spec.Remember != r.Remember {
		t.Fatal("guest elevation or remember replacement")
	}
	var consumed bool
	if err := pool.Raw().QueryRow(ctx, `SELECT state='consumed' FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(r.TenantID), string(r.PreAuthID)).Scan(&consumed); err != nil || !consumed {
		t.Fatal("original preauth not atomically consumed", err)
	}
	reader, err := anonymouspg.NewSessionService(pool, anonymouspg.SessionServiceConfig{Repository: config.Repository, Sessions: config.Sessions, Profile: config.Profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Clock: clock.System{}, MaximumDuration: 3 * time.Second, ClockUncertainty: time.Millisecond, Audience: config.Profile.Audience, LookupKeys: []session.DigestKey{lookupKey}}})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := session.NewCredential(session.CredentialBearer, result.Session.Token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reader.Get(ctx, session.GetRequest{TenantID: r.TenantID, Credential: credential})
	if err != nil || !got.Recognized {
		t.Fatal("issued guest cannot be read", err)
	}
	repeated, err := issuer.Signin(ctx, r)
	if err != nil || repeated.Outcome != identity.CommitOutcomeCommitted || !repeated.Replayed || repeated.Session.Token != (session.Token{}) || repeated.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("keyed replay generated/revealed another session", err)
	}
	changed := r
	changed.Device = "different-device"
	if out, err := issuer.Signin(ctx, changed); err == nil || out.Session.Token != (session.Token{}) {
		t.Fatal("changed keyed intent admitted")
	}
	freshService, err := anonymouspg.NewSigninService(pool, config, keys)
	if err != nil {
		t.Fatal(err)
	}
	historical, err := freshService.RecoverSignin(ctx, anonymous.SigninRecoveryRequest{Recovery: result.Recovery, Cookie: r.Cookie, Caller: r.Caller.Clone(), Origin: r.Origin, Network: r.Network, Device: r.Device})
	if err != nil || historical.Outcome != identity.CommitOutcomeCommitted || historical.Session.Token != (session.Token{}) || historical.CSRFToken != (session.CSRFToken{}) {
		t.Fatal("fresh-service original metadata recovery", err)
	}
	var subjects, sessions int
	if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM anonymous_store.subjects),(SELECT count(*) FROM session_store.sessions)`).Scan(&subjects, &sessions); err != nil || subjects != 1 || sessions != 1 {
		t.Fatal("keyed/recovery repeated effects", err)
	}
	wrong := fresh()
	wrong.Cookie = r.Cookie
	if out, err := issuer.Signin(ctx, wrong); err == nil || out.Session.Token != (session.Token{}) {
		t.Fatal("foreign original cookie admitted")
	}
	// These faults occur in the actual required owners, after provisional guest
	// and session writes. A nontransactional sequence proves that exact boundary
	// was reached even though every protected row must roll back.
	if _, err := pool.Raw().Exec(ctx, `CREATE SEQUENCE public.anonymous_late_fault_reached;
CREATE FUNCTION public.anonymous_late_fault() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (SELECT count(*) FROM anonymous_store.subjects)<>2 OR
    (SELECT count(*) FROM session_store.sessions)<>2 THEN
  RAISE EXCEPTION 'fault did not reach provisional identity and session';
 END IF;
 PERFORM nextval('public.anonymous_late_fault_reached');
 RAISE EXCEPTION 'injected anonymous required effect failure';
END $$;`); err != nil {
		t.Fatal("install owned late-effect fault", err)
	}
	for i, test := range []struct{ name, table, condition string }{
		{"audit", "audit.records", fmt.Sprintf("NEW.action='identity.anonymous.create' AND NEW.outcome=%d", audit.OutcomeSucceeded)},
		{"outbox", "public.outbox_messages", "NEW.topic='anonymous.created.v1'"},
	} {
		t.Run("required-"+test.name+"-rollback", func(t *testing.T) {
			request := fresh()
			if _, err := pool.Raw().Exec(ctx, "CREATE TRIGGER anonymous_late_fault AFTER INSERT ON "+test.table+" FOR EACH ROW WHEN ("+test.condition+") EXECUTE FUNCTION public.anonymous_late_fault()"); err != nil {
				t.Fatal("install exact owned fault", err)
			}
			defer func() {
				if _, err := pool.Raw().Exec(ctx, "DROP TRIGGER anonymous_late_fault ON "+test.table); err != nil {
					t.Error("remove exact owned fault", err)
				}
			}()
			out, err := issuer.Signin(ctx, request)
			if err == nil || out.Outcome != identity.CommitOutcomeNotCommitted || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("late required failure disclosed or failed to prove rollback", err, out.Outcome)
			}
			var reached int64
			var called bool
			if err := pool.Raw().QueryRow(ctx, `SELECT last_value,is_called FROM public.anonymous_late_fault_reached`).Scan(&reached, &called); err != nil || !called || reached != int64(i+1) {
				t.Fatal("fault did not reach both provisional effects", err)
			}
			var users, subjects, sessions, lifecycle int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM anonymous_store.subjects),(SELECT count(*) FROM session_store.sessions),(SELECT count(*) FROM public.outbox_messages WHERE topic='anonymous.created.v1')`).Scan(&users, &subjects, &sessions, &lifecycle); err != nil || users != 1 || subjects != 1 || sessions != 1 || lifecycle != 1 {
				t.Fatal("required failure leaked protected effects", err)
			}
			var issued bool
			if err := pool.Raw().QueryRow(ctx, `SELECT state='issued' FROM session_store.preauth_transactions WHERE tenant_id=$1 AND flow_id=$2`, string(request.TenantID), string(request.PreAuthID)).Scan(&issued); err != nil || !issued {
				t.Fatal("late rollback consumed original browser", err)
			}
			historical, err := freshService.RecoverSignin(ctx, anonymous.SigninRecoveryRequest{Recovery: out.Recovery, Cookie: request.Cookie, Caller: request.Caller.Clone(), Origin: request.Origin, Network: request.Network, Device: request.Device})
			if err == nil || historical.Outcome != identity.CommitOutcomeNotCommitted || historical.Session.Token != (session.Token{}) || historical.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("failed original recovery invented commit or disclosed", err, historical.Outcome)
			}
		})
	}
	for _, before := range []bool{true, false} {
		t.Run(fmt.Sprintf("lost-commit-before=%t", before), func(t *testing.T) {
			request := fresh()
			fault := &anonymousCommitFault{before: before}
			faultPool, err := database.Connect(ctx, database.Config{DSN: pool.Raw().Config().ConnConfig.ConnString(), MaxConns: 3, Configure: func(c *database.PoolConfig) error {
				// ConnString retains its original parse input; the fixture selected
				// its disposable database through Configure, not by rewriting DSN.
				c.ConnConfig.Database = pool.Raw().Config().ConnConfig.Database
				c.ConnConfig.DialFunc = fault.dial
				return nil
			}})
			if err != nil {
				t.Fatal("owned transport fault pool", err)
			}
			defer func() {
				bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
				defer stop()
				if err := faultPool.Close(bounded); err != nil {
					t.Error("owned fault pool cleanup", err)
				}
			}()
			var selected string
			if err := faultPool.Raw().QueryRow(ctx, `SELECT current_database()`).Scan(&selected); err != nil || selected != pool.Raw().Config().ConnConfig.Database {
				t.Fatal("transport fault selected a different fixture database", err)
			}
			faultConfig := config
			faultConfig.Coordinator.LeaseDuration = 3 * time.Second
			faultService, err := anonymouspg.NewSigninService(faultPool, faultConfig, keys)
			if err != nil {
				t.Fatal(err)
			}
			out, err := faultService.Signin(ctx, request)
			var unknown identity.UnknownCommitError
			if !errors.As(err, &unknown) || out.Outcome != identity.CommitOutcomeUnknown || !fault.hit.Load() || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("real COMMIT fault lost ambiguity or disclosed credentials", err, out.Outcome)
			}
			expected, count := identity.CommitOutcomeCommitted, 2
			if before {
				expected, count = identity.CommitOutcomeNotCommitted, 1
			}
			recovery := anonymous.SigninRecoveryRequest{Recovery: out.Recovery, Cookie: request.Cookie, Caller: request.Caller.Clone(), Origin: request.Origin, Network: request.Network, Device: request.Device}
			deadline := time.NewTimer(5 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(25 * time.Millisecond)
			defer tick.Stop()
			for {
				historical, err := freshService.RecoverSignin(ctx, recovery)
				if historical.Session.Token != (session.Token{}) || historical.CSRFToken != (session.CSRFToken{}) {
					t.Fatal("ambiguous recovery disclosed credentials")
				}
				if historical.Outcome == expected {
					if expected == identity.CommitOutcomeCommitted && err != nil {
						t.Fatal("committed recovery failed", err)
					}
					break
				}
				select {
				case <-deadline.C:
					t.Fatal("original ambiguous command did not reconcile", err, historical.Outcome)
				case <-ctx.Done():
					t.Fatal("original recovery budget exhausted")
				case <-tick.C:
				}
			}
			var users, subjects, sessions int
			if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM anonymous_store.subjects),(SELECT count(*) FROM session_store.sessions)`).Scan(&users, &subjects, &sessions); err != nil || users != count || subjects != count || sessions != count {
				t.Fatal("ambiguous outcome disagrees with actual protected rows", err)
			}
			repeated, err := issuer.Signin(ctx, request)
			if repeated.Outcome != expected || repeated.Session.Token != (session.Token{}) || repeated.CSRFToken != (session.CSRFToken{}) || !before && (err != nil || !repeated.Replayed) {
				t.Fatal("original ambiguous retry repeated execution or reveal", err, repeated.Outcome)
			}
		})
	}
	t.Run("same-original-contention", func(t *testing.T) {
		request := fresh()
		type answer struct {
			result anonymous.SigninResult
			err    error
		}
		const clients = 5
		start := make(chan struct{})
		answers := make(chan answer, clients)
		var done sync.WaitGroup
		for range clients {
			done.Add(1)
			go func() {
				defer done.Done()
				<-start
				out, err := issuer.Signin(ctx, request)
				answers <- answer{out, err}
			}()
		}
		close(start)
		done.Wait()
		close(answers)
		deliveries := 0
		var original anonymous.SigninRecovery
		for answer := range answers {
			out := answer.result
			if answer.err != nil || out.Outcome != identity.CommitOutcomeCommitted && out.Outcome != identity.CommitOutcomeInProgress {
				t.Fatal("same original contention changed outcome", answer.err, out.Outcome)
			}
			if out.Session.Token != (session.Token{}) {
				deliveries++
				if out.Outcome != identity.CommitOutcomeCommitted || out.Replayed || out.CSRFToken == (session.CSRFToken{}) {
					t.Fatal("nonwinner disclosed credentials")
				}
			} else if out.CSRFToken != (session.CSRFToken{}) {
				t.Fatal("contention disclosed orphan CSRF")
			}
			if original != (anonymous.SigninRecovery{}) && out.Recovery != original {
				t.Fatal("one key selected different original identities")
			}
			original = out.Recovery
		}
		if deliveries != 1 {
			t.Fatal("one original did not reveal exactly once", deliveries)
		}
		var users, subjects, sessions int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM anonymous_store.subjects),(SELECT count(*) FROM session_store.sessions)`).Scan(&users, &subjects, &sessions); err != nil || users != 3 || subjects != 3 || sessions != 3 {
			t.Fatal("one original repeated protected effects under contention", err)
		}
	})
	t.Run("required-risk-owner-unavailable", func(t *testing.T) {
		request := fresh()
		if _, err := pool.Raw().Exec(ctx, `ALTER TABLE risk_store.durable_counter_scopes RENAME TO unavailable_counter_scopes`); err != nil {
			t.Fatal("owned risk outage", err)
		}
		defer func() {
			if _, err := pool.Raw().Exec(ctx, `ALTER TABLE risk_store.unavailable_counter_scopes RENAME TO durable_counter_scopes`); err != nil {
				t.Error("owned risk restoration", err)
			}
		}()
		out, err := issuer.Signin(ctx, request)
		if err == nil || out.Session.Token != (session.Token{}) || out.CSRFToken != (session.CSRFToken{}) || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("unavailable required risk owner admitted guest")
		}
		var users, subjects, sessions int
		if err := pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM anonymous_store.subjects),(SELECT count(*) FROM session_store.sessions)`).Scan(&users, &subjects, &sessions); err != nil || users != 3 || subjects != 3 || sessions != 3 {
			t.Fatal("unavailable risk owner leaked protected effects", err)
		}
	})
}
