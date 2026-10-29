//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	"github.com/faustbrian/go-identity/delivery"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationpg "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Only these explicit provider seams are controlled. Capability issuance,
// encrypted queue custody, worker transitions and HIBP parsing remain native.
type registrationMailbox struct {
	mu   sync.Mutex
	body string
}

func (m *registrationMailbox) Send(ctx context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
	if ctx == nil || ctx.Err() != nil || a.Validate() != nil || a.TenantID != baselineTenant || len(a.Body) > 4096 {
		return delivery.DeliveryResult{}, delivery.ErrInvalidInput
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.body != "" {
		return delivery.DeliveryResult{}, delivery.ErrUnavailable
	}
	m.body = strings.Clone(a.Body)
	return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
}

type hibpTransport struct{}

func (hibpTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Context().Err() != nil {
		return nil, r.Context().Err()
	}
	if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "api.pwnedpasswords.com" || !strings.HasPrefix(r.URL.Path, "/range/") || len(r.URL.Path) != 12 {
		return nil, io.ErrUnexpectedEOF
	}
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("0", 35) + ":0\r\n")), Request: r}, nil
}

func consumerDatabase(t *testing.T) (context.Context, *database.Pool, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("GOLIB_APIKEY_TEST_POSTGRES_DSN")
	parsed, e := pgx.ParseConfig(dsn)
	if dsn == "" || e != nil || parsed.Host != "127.0.0.1" {
		t.Fatal("explicit task-owned loopback PostgreSQL fixture required")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal("isolated primary unavailable")
	}
	var existing int
	if e = admin.QueryRow(ctx, `SELECT count(*) FROM pg_roles WHERE rolname IN ('audit_writer','audit_reader','audit_retention')`).Scan(&existing); e != nil || existing != 0 {
		_ = admin.Close(ctx)
		t.Fatal("consumer fixture requires absent native audit roles")
	}
	id, e := identity.NewSubjectID()
	if e != nil {
		t.Fatal(e)
	}
	name := "api_key_consumer_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+quoted); e != nil {
		t.Fatal("consumer database creation failed")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, e := admin.Exec(cleanup, "DROP DATABASE "+quoted); e != nil {
			t.Error("consumer database cleanup failed")
		}
		if _, e := admin.Exec(cleanup, "DROP ROLE IF EXISTS audit_writer,audit_reader,audit_retention"); e != nil {
			t.Error("consumer audit-role cleanup failed")
		}
		_ = admin.Close(cleanup)
	})
	parsed.Database = name
	parsed.RuntimeParams["search_path"] = "public"
	db := stdlib.OpenDB(*parsed)
	t.Cleanup(func() { _ = db.Close() })
	pool, e := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(c *database.PoolConfig) error {
		c.ConnConfig.Database = name
		c.ConnConfig.RuntimeParams["search_path"] = "public"
		return nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("consumer pool cleanup failed")
		}
	})
	return ctx, pool, db
}

type migrationList []migrations.Migration

func (s migrationList) Load(ctx context.Context) ([]migrations.Migration, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]migrations.Migration(nil), s...), nil
}
func commandID(t *testing.T) identity.CommandID {
	t.Helper()
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The complete owned path begins with the public signup/verification/password
// signin graph. Only mail delivery and the external HIBP HTTP response are
// controlled. No user, credential, session, current-authority or key store is
// fabricated. The returned bearer is exactly the actual issued session token.
func genuineUser(t *testing.T, ctx context.Context, pool *database.Pool, graph *baselineGraph, server *httptest.Server, origin string, mailbox *registrationMailbox, sessions *session.SessionService, material func(string) []byte) (apikey.Authentication, identity.UserID) {
	t.Helper()
	client := server.Client()
	client.Timeout = 6 * time.Second
	client.Jar, _ = cookiejar.New(nil)
	call := func(path string, body any, key string) (int, []byte, []*http.Cookie) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", origin)
		if key != "" {
			request.Header.Set("Idempotency-Key", key)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("public signup/signin HTTPS unavailable")
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 16385))
		closed := response.Body.Close()
		if readErr != nil || closed != nil || len(payload) > 16384 || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("public response bounds failed")
		}
		return response.StatusCode, payload, response.Cookies()
	}
	preauth := func(method string) sessionhttp.PreAuthResponse {
		t.Helper()
		status, body, _ := call("/v1/session/preauth-issue", map[string]string{"method": method}, "")
		var out sessionhttp.PreAuthResponse
		if status != 200 || json.Unmarshal(body, &out) != nil || !out.Issued {
			t.Fatal("pre-Create genuine preauth rejected", status)
		}
		return out
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal("fixture entropy unavailable")
	}
	address := "api-key-" + hex.EncodeToString(random[:8]) + "@example.invalid"
	candidate := hex.EncodeToString(random[:])
	clear(random[:])
	flow := preauth("signup")
	status, body, cookies := call("/v1/password/signup", map[string]any{"flowID": string(flow.FlowID), "email": address, "password": candidate, "callbackURL": origin + "/confirm"}, "api-key-signup-"+string(flow.FlowID))
	var signup passwordhttp.SignupResponse
	decodeErr := json.Unmarshal(body, &signup)
	if status != 200 || decodeErr != nil || !signup.VerificationRequired || signup.CommitOutcome != "committed" || len(cookies) != 0 {
		t.Fatalf("pre-Create genuine signup failed: status=%d decoded=%t unknown=%t unavailable=%t recovery_present=%t command_present=%t parent_done=%t primitive=%v", status, decodeErr == nil, signup.CommitOutcome == "unknown", signup.Error == "unavailable", signup.Recovery != nil, signup.CommandID != "", ctx.Err() != nil, graph.password.snapshot())
	}
	if _, err := graph.workers.ProcessDeliveryOne(ctx, 0); err != nil {
		t.Fatal("pre-Create genuine verification delivery failed", err)
	}
	mailbox.mu.Lock()
	link := mailbox.body
	mailbox.body = ""
	mailbox.mu.Unlock()
	parsed, err := url.Parse(link)
	if err != nil || parsed.Query().Get("token") == "" {
		t.Fatal("genuine verification capability absent")
	}
	status, body, cookies = call("/v1/email/verification-confirm", map[string]string{"token": parsed.Query().Get("token"), "callback": origin + "/confirm", "commandID": string(commandID(t))}, "")
	var confirmation emailhttp.ConfirmationResponse
	if status != 200 || json.Unmarshal(body, &confirmation) != nil || !confirmation.Confirmed || confirmation.CommitOutcome != "committed" || len(cookies) != 0 {
		t.Fatal("pre-Create genuine verification failed", status)
	}
	service := apiKeySigninService(t, ctx, pool, graph, material)
	caller, user := genuineAPIKeySignin(t, ctx, pool, graph.signin, service, address, candidate)
	token, err := session.ParseToken(caller.Bearer.Token())
	if err != nil {
		t.Fatal("actual issued token rejected")
	}
	credential, err := session.NewCredential(session.CredentialBearer, token)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := sessions.Get(ctx, session.GetRequest{TenantID: baselineTenant, Credential: credential})
	if err != nil || observed.ValidateAt(time.Now()) != nil {
		t.Fatal("actual primary session owner rejected signup/signin result", err)
	}
	bound, err := observed.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	if bound.UserID != user || observed.Session.CSRFState() != (session.CSRFState{}) {
		t.Fatal("native bearer signin changed user or inherited browser synchronizer")
	}
	return caller, bound.UserID
}

type nativeConsumerFixture struct {
	ctx                           context.Context
	pool                          *database.Pool
	db                            *sql.DB
	config                        apikeypg.ServiceConfig
	caller                        apikey.Authentication
	user                          identity.UserID
	maximumGrants                 []string
	deniedGrant, deniedManagement *atomic.Bool
	register                      func() (apikey.Authentication, identity.UserID)
}

func setupNativeConsumer(t *testing.T) nativeConsumerFixture {
	t.Helper()
	ctx, pool, db := consumerDatabase(t)
	names := []string{"fingerprint", "request", "counter", "risk-evidence", "risk-seal", "preauth-cookie", "session-token", "session-csrf", "http-device", "delivery-envelope", "dummy-password", "capability-binding", "capability-signing", "signin-proof", "migration", "counter-replay", "http-rate", "otp-lockout", "otp-wrap", "otp-attempt", "otp-code", "otp-intent", "identifier", "delivery-digest", "delivery-namespace", "password-flow", "signup-binding", "signup-intent", "verification-scope", "capability-replay", "capability-envelope", "counter-envelope", "verification-http", "api-key-pepper", "api-key-envelope"}
	keys := make(map[string][32]byte, len(names))
	for _, name := range names {
		var key [32]byte
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal("fixture entropy unavailable")
		}
		keys[name] = key
	}
	t.Cleanup(func() { clear(keys) })
	material := func(name string) []byte { key := keys[name]; return append([]byte(nil), key[:]...) }
	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	origin := "https://" + server.Listener.Addr().String()
	mailbox := &registrationMailbox{}
	t.Cleanup(func() { mailbox.mu.Lock(); mailbox.body = ""; mailbox.mu.Unlock() })
	graph, err := fixtureGraph(ctx, origin, keys, pool, mailbox, hibpTransport{})
	if err != nil {
		t.Fatal("pre-Create public native graph configuration failed", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if graph.close(cleanup) != nil {
			t.Error("public graph cleanup failed")
		}
	})
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity"}
	plan, err := graph.stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: modules})
	if err != nil {
		t.Fatal("pre-Create public migration plan failed", err)
	}
	install, err := identity.NewIdempotencyKey([]byte("api-key-real-consumer-install"))
	if err != nil {
		t.Fatal(err)
	}
	applied, err := graph.stores.ReferenceMigrationApply(ctx, reference.ReferenceMigrationApplyRequest{CommandID: "api_key_real_consumer_install", Plan: plan.Plan, IdempotencyKey: install})
	if err != nil || applied.Result.State() != reference.MigrationApplied {
		t.Fatal("pre-Create public migrations failed", applied.Result.State())
	}
	kernelSteps, err := (kernel.CounterPreparationMigrationSource{Base: graph.stores.MigrationSource(), Version: 1700}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	riskBase := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: "risk_store", Version: 1}, Version: 2}, Version: 3}, Version: 4}
	riskSteps, err := (riskpg.LockoutMigrationSource{Base: riskBase, Version: 5}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	keySteps, err := (apikeypg.MigrationSource{Version: 7100}).Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, extension := range []struct {
		namespace string
		steps     []migrations.Migration
	}{{"identity_password_change_kernel", kernelSteps[len(kernelSteps)-1:]}, {"identity_risk_lockouts", riskSteps[len(riskSteps)-1:]}, {"identity_api_keys", keySteps}} {
		backend, err := migrationpg.New(db)
		if err != nil {
			t.Fatal(err)
		}
		backend, err = backend.ForNamespace(extension.namespace)
		if err != nil {
			t.Fatal(err)
		}
		runner, err := migrations.NewRunner(migrationList(extension.steps), backend)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.Up(ctx); err != nil {
			t.Fatal("pre-Create public/native migration failed", err)
		}
	}
	if err := graph.features.Initialize(ctx); err != nil {
		t.Fatal("pre-Create native graph initialization failed", err)
	}
	server.Config.Handler = graph.server.Handler()
	server.StartTLS()
	lookup, err := session.NewDigestKey(11, material("session-token"))
	if err != nil {
		t.Fatal(err)
	}
	profile := sessionpg.IdentifierAdmissionConfig{GlobalAuthorityID: "deployment", PolicyNamespace: "users", Audience: "local-baseline", AuthenticationMethod: "password", CredentialKind: identity.CredentialPassword, CredentialOwner: "identity/password"}
	sessionStore := sessionpg.Config{Schema: "session_store", MaximumDuration: time.Second}
	sessions, err := sessionpg.NewSessionService(pool, sessionpg.SessionServiceConfig{Repository: sessionStore, Profile: profile, Validation: session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: profile.Audience, Clock: clock.System{}, MaximumDuration: 2 * time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{lookup}}})
	if err != nil {
		t.Fatal(err)
	}
	caller, user := genuineUser(t, ctx, pool, graph, server, origin, mailbox, sessions, material)
	var deniedGrant, deniedManagement atomic.Bool
	maximumGrants := make([]string, 64)
	for i := range maximumGrants {
		maximumGrants[i] = fmt.Sprintf("%02d%s", i, strings.Repeat("&", 126))
	}
	authorize, err := fixtureAuthorization(&baselineEvaluator{deniedGrant: &deniedGrant, deniedManagement: &deniedManagement, additionalPermissions: maximumGrants})
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: authorize, PolicyVersion: 9}
	requestKeys, err := kernel.NewRequestKeyConfig("api-key-consumer", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := baselineRiskPolicy(9, false, false)
	if err != nil {
		t.Fatal(err)
	}
	counter, err := risk.NewCounterDigestKey(1, material("counter"))
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, material("risk-evidence"), material("risk-seal"))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := riskpg.NewRepository(riskpg.Config{Schema: "risk_store", PolicyVersion: 9, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: policy, Keys: []risk.CounterDigestKey{counter}}, EnforceLockouts: true})
	if err != nil {
		t.Fatal(err)
	}
	// Protected provider preparation must never replace velocity. The sole real
	// native counter participant owns it, and this source denies if ever called.
	evaluation, err := risk.NewEvaluator(risk.EvaluatorConfig{Policy: policy, Clock: time.Now, Timeout: time.Second, Sources: []risk.Source{{Name: "velocity", Version: "native-counter-deferred-v1", Timeout: time.Second, Read: func(context.Context, risk.Context) (risk.Signal, error) {
		return risk.Signal{}, risk.ErrUnsupportedIssuance
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	pepper, err := apikey.NewPepper(1, material("api-key-pepper"))
	if err != nil {
		t.Fatal(err)
	}
	configuration, err := apikey.NewConfiguration(apikey.ConfigurationSpec{ID: "automation", Revision: 1, State: apikey.ConfigurationActive, Issuer: origin, Environment: "consumer", Audience: "resource-api", PermissionReduction: apikey.PermissionReductionNarrow, MaximumLifetime: 90 * 24 * time.Hour, MaximumRead: 4 * time.Second, ClockUncertainty: time.Millisecond + time.Nanosecond, DecisionRaceBudget: time.Millisecond, Quota: apikey.QuotaUnlimited, Cache: apikey.CacheDisabled})
	if err != nil {
		t.Fatal(err)
	}
	c := apikeypg.ServiceConfig{Configuration: configuration, Clock: clock.System{}, MaximumDuration: 4 * time.Second, Sessions: sessions, Session: sessionStore, Profile: profile, LookupKeys: map[uint32]session.DigestKey{11: lookup}, Authorization: authorize, PolicyID: "api-key-policy", PolicyVersion: 9, Pepper: pepper, Counters: counters, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluation, ConfigurationID: "api-key-providers-v1", Keys: []risk.EvidenceKey{evidence}}, CounterPolicy: policy, Coordinator: kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}, RequestKeys: requestKeys, ActiveEnvelopeKeyID: "api-key-envelope", RetainedEnvelopeKeys: map[string][]byte{"api-key-envelope": material("api-key-envelope")}}
	return nativeConsumerFixture{ctx: ctx, pool: pool, db: db, config: c, caller: caller, user: user, maximumGrants: maximumGrants, deniedGrant: &deniedGrant, deniedManagement: &deniedManagement, register: func() (apikey.Authentication, identity.UserID) {
		return genuineUser(t, ctx, pool, graph, server, origin, mailbox, sessions, material)
	}}
}

func TestGenuinePasswordCreateCommitsBeforeOneTimeReveal(t *testing.T) {
	f := setupNativeConsumer(t)
	ctx, pool, c, caller, user := f.ctx, f.pool, f.config, f.caller, f.user
	maximumGrants, deniedGrant, deniedManagement := f.maximumGrants, f.deniedGrant, f.deniedManagement
	if !t.Run("unsupported-revoke-policy", func(t *testing.T) {
		spec := c.Configuration.Spec()
		spec.PermissionReduction = apikey.PermissionReductionRevoke
		revoke, err := apikey.NewConfiguration(spec)
		if err != nil {
			t.Fatal("root configuration no longer permits the distinct Revoke profile", err)
		}
		unsupported := c
		unsupported.Configuration = revoke
		if service, err := apikeypg.NewService(pool, unsupported); service != nil || !errors.Is(err, apikey.ErrInvalid) {
			t.Fatal("Narrow-only native service accepted Revoke without its required lifecycle", err)
		}
	}) {
		return
	}
	s, err := apikeypg.NewService(pool, c)
	if err != nil {
		t.Fatal("native Create configuration rejected", err)
	}
	if err := s.InitializeConfiguration(ctx, baselineTenant); err != nil {
		t.Fatal("explicit native configuration provisioning failed", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("api-key-consumer-original-create"))
	if err != nil {
		t.Fatal(err)
	}
	request := apikey.CreateRequest{Authentication: caller, IdempotencyKey: key, Name: "automation", Permissions: []string{"invoice.read", "invoice.write"}, ExpiresAt: time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond), CorrelationID: "api-key-consumer-create", Network: "192.0.2.1"}
	issued, err := s.Create(ctx, request)
	if err != nil {
		t.Fatal("actual API-key Create failed", err)
	}
	receipt, err := issued.Receipt()
	if err != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("Create did not prove commitment")
	}
	record, ok := issued.Record()
	if !ok || record.Owner.Spec().UserID != user || record.Owner.Spec().TenantID != baselineTenant || record.Version != 1 || record.RootID != record.ID || record.RootVersion != 1 {
		t.Fatal("Create changed actual owner/root")
	}
	wire, err := issued.Reveal()
	if err != nil || len(wire) != 47 || !strings.HasPrefix(wire, "idk_") {
		t.Fatal("known committed original key not delivered")
	}
	if _, err := issued.Reveal(); !errors.Is(err, apikey.ErrAlreadyRevealed) {
		t.Fatal("original key revealed twice")
	}
	restarted, err := apikeypg.NewService(pool, c)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Create(ctx, request)
	if err != nil {
		t.Fatal("matching original creation retry failed", err)
	}
	replayedReceipt, err := replayed.Receipt()
	if err != nil || replayedReceipt.Binding != receipt.Binding || replayedReceipt.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("retry changed original outcome")
	}
	if _, err := replayed.Reveal(); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatal("restart/retry reconstructed original plaintext")
	}
	// The public application policy's current denial is not the coordinator's
	// request-admission/query policy. A retained mapping grants neither original
	// key-management nor withdrawn permission disclosure authority.
	t.Run("current-grant-denies-retained-retry", func(t *testing.T) {
		deniedGrant.Store(true)
		defer deniedGrant.Store(false)
		denied, err := restarted.Create(ctx, request)
		if !errors.Is(err, apikey.ErrDenied) || denied.DeliveryOutcome() != apikey.IssuanceUnspecified {
			t.Fatal("retained original bypassed current permission policy")
		}
	})
	t.Run("current-management-denies-retained-retry", func(t *testing.T) {
		deniedManagement.Store(true)
		defer deniedManagement.Store(false)
		denied, err := restarted.Create(ctx, request)
		if !errors.Is(err, apikey.ErrDenied) || denied.DeliveryOutcome() != apikey.IssuanceUnspecified {
			t.Fatal("retained original bypassed current key-management policy")
		}
	})
	var stored, events int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_api_keys.keys WHERE tenant_id=$1 AND user_id=$2`, baselineTenant, string(user)).Scan(&stored); err != nil || stored != 1 {
		t.Fatal("original request minted another key")
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_api_keys.command_effects WHERE command_id=$1`, string(receipt.Binding.CommandID)).Scan(&events); err != nil || events != 1 {
		t.Fatal("original creation effects not durable/exactly once")
	}
	if !t.Run("maximum-escaped-grants", func(t *testing.T) {
		exerciseMaximumGrantVerification(t, ctx, restarted, c, request, maximumGrants)
	}) {
		return
	}
	exerciseRotationRevocation(t, ctx, pool, restarted, c, request, deniedGrant, deniedManagement)
	exerciseAtomicVerification(t, ctx, pool, restarted, c, request, wire, record, deniedGrant)
}

func exerciseMaximumGrantVerification(t *testing.T, ctx context.Context, s *apikeypg.Service, c apikeypg.ServiceConfig, create apikey.CreateRequest, permissions []string) {
	t.Helper()
	create.Name, create.Permissions = "maximum-permission-ceiling", slices.Clone(permissions)
	var err error
	create.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("api-key-maximum-escaped-grant"))
	if err != nil {
		t.Fatal(err)
	}
	issued, err := s.Create(ctx, create)
	if err != nil {
		t.Fatal("maximum supported permission ceiling could not be issued", err)
	}
	record, ok := issued.Record()
	if !ok || !slices.Equal(record.Grant, permissions) {
		t.Fatal("issued maximum grant was truncated or changed")
	}
	wire, err := issued.Reveal()
	if err != nil {
		t.Fatal("maximum-grant key was not revealed after commitment", err)
	}
	secret, err := apikey.ParseSecret(wire)
	if err != nil {
		t.Fatal(err)
	}
	request := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: create.Authentication.TenantID, ConfigurationID: c.Configuration.Spec().ID, ConfigurationRevision: c.Configuration.Spec().Revision, Secret: secret, RequiredPermissions: []string{permissions[0], permissions[len(permissions)-1]}}
	verified, err := s.VerifyAndConsume(ctx, request)
	if err != nil || verified.Validate() != nil || verified.Result == nil || verified.Result.ValidateAt(c.Configuration, time.Now()) != nil || !slices.Equal(verified.Result.Grant, permissions) {
		t.Fatal("issued maximum-grant key could not authenticate", err)
	}
	replayed, err := s.VerifyAndConsume(ctx, request)
	if err != nil || replayed.Fingerprint != verified.Fingerprint || replayed.Result == nil || !slices.Equal(replayed.Result.Grant, permissions) || !replayed.Result.ReadStartedAt.Equal(verified.Result.ReadStartedAt) || !replayed.Result.ValidUntil.Equal(verified.Result.ValidUntil) {
		t.Fatal("maximum-grant replay changed original result or freshness", err)
	}
	reconciled, err := s.ReconcileVerifyAndConsume(ctx, apikey.VerificationReconcileQuery{AttemptID: verified.AttemptID, TenantID: request.TenantID, Fingerprint: verified.Fingerprint, Original: verified.Original})
	if err != nil || reconciled.Result == nil || !slices.Equal(reconciled.Result.Grant, permissions) || !reconciled.Result.ReadStartedAt.Equal(verified.Result.ReadStartedAt) || !reconciled.Result.ValidUntil.Equal(verified.Result.ValidUntil) {
		t.Fatal("maximum-grant reconciliation lost original authority", err)
	}
}

func exerciseRotationRevocation(t *testing.T, ctx context.Context, pool *database.Pool, s *apikeypg.Service, c apikeypg.ServiceConfig, create apikey.CreateRequest, deniedGrant, deniedManagement *atomic.Bool) {
	t.Helper()
	configuration := c.Configuration.Spec()
	configuration.ID = "rotation"
	var err error
	c.Configuration, err = apikey.NewConfiguration(configuration)
	if err != nil {
		t.Fatal(err)
	}
	s, err = apikeypg.NewService(pool, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.InitializeConfiguration(ctx, create.Authentication.TenantID); err != nil {
		t.Fatal(err)
	}
	key := func(value string) identity.IdempotencyKey {
		out, err := identity.NewIdempotencyKey([]byte(value))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	create.IdempotencyKey = key("rotation-original-create")
	original, err := s.Create(ctx, create)
	if err != nil {
		t.Fatal("rotation fixture issuance failed", err)
	}
	before, ok := original.Record()
	if !ok {
		t.Fatal("rotation predecessor missing")
	}
	oldWire, err := original.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	request := apikey.Rotation{Authentication: create.Authentication, IdempotencyKey: key("rotation-original-request"), KeyID: before.ID, ExpectedVersion: before.Version, CorrelationID: "native-rotation", Network: create.Network}
	stale := request
	stale.ExpectedVersion++
	stale.IdempotencyKey = key("rotation-stale-version")
	if out, err := s.Rotate(ctx, stale); out.DeliveryOutcome() != apikey.IssuanceUnspecified {
		t.Fatal("stale rotation produced an outcome")
	} else {
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) {
			t.Fatal("known-owner stale CAS did not conflict before mutation", err)
		}
	}
	rollback := request
	rollback.IdempotencyKey = key("rotation-required-audit-rollback")
	rejectMutationAudit(t, ctx, pool, "identity.api_key.rotate", func() {
		out, err := s.Rotate(ctx, rollback)
		if err == nil || out.DeliveryOutcome() == apikey.IssuanceCommittedAndRevealed || out.DeliveryOutcome() == apikey.IssuanceCommittedDeliveryUnknown {
			t.Fatal("rotation survived required audit failure")
		}
		if _, err := out.Reveal(); !errors.Is(err, apikey.ErrDisclosure) {
			t.Fatal("rolled-back rotation revealed material")
		}
	})
	assertStoredKeyState(t, ctx, pool, create.Authentication.TenantID, before.ID, apikey.KeyActive, before.Version, before.AuthorityVersion)
	rotated, err := s.Rotate(ctx, request)
	if err != nil {
		t.Fatal("native rotation failed", err)
	}
	after, ok := rotated.Record()
	if !ok || after.ID == before.ID || after.PreviousID != before.ID || after.RootID != after.ID || after.RootVersion != 1 || after.Version != 1 || after.AuthorityVersion != 1 || !after.Owner.SameIdentity(before.Owner) || !after.ExpiresAt.Equal(before.ExpiresAt) || strings.Join(after.Grant, ",") != strings.Join(before.Grant, ",") {
		t.Fatal("rotation renewed authority or lost credential lineage")
	}
	newWire, err := rotated.Reveal()
	if err != nil || newWire == oldWire {
		t.Fatal("rotation did not reveal a distinct modern successor")
	}
	if _, err := rotated.Reveal(); !errors.Is(err, apikey.ErrAlreadyRevealed) {
		t.Fatal("rotation revealed successor twice")
	}
	restarted, err := apikeypg.NewService(pool, c)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := restarted.Rotate(ctx, request)
	if err != nil {
		t.Fatal("rotation retained retry failed", err)
	}
	replayedRecord, ok := replayed.Record()
	if !ok || replayedRecord.ID != after.ID {
		t.Fatal("rotation retry minted a different successor")
	}
	if _, err := replayed.Reveal(); !errors.Is(err, apikey.ErrDisclosure) {
		t.Fatal("rotation retry reconstructed successor plaintext")
	}
	for _, denied := range []*atomic.Bool{deniedGrant, deniedManagement} {
		denied.Store(true)
		out, retryErr := restarted.Rotate(ctx, request)
		denied.Store(false)
		if !errors.Is(retryErr, apikey.ErrDenied) || out.DeliveryOutcome() != apikey.IssuanceUnspecified {
			t.Fatal("retained rotation bypassed current authority")
		}
	}
	query, err := rotated.Recovery()
	if err != nil {
		t.Fatal(err)
	}
	status, err := restarted.Recover(ctx, apikey.RecoveryRequest{Authentication: create.Authentication, Query: query})
	if err != nil || status.Binding.CommandID != query.CommandID || status.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("rotation raw-free original recovery failed", err)
	}
	changed := request
	changed.ExpectedVersion++
	if _, err := restarted.Rotate(ctx, changed); err == nil {
		t.Fatal("rotation accepted changed original intent")
	}
	verify := func(raw string, allowed bool) {
		t.Helper()
		secret, err := apikey.ParseSecret(raw)
		if err != nil {
			t.Fatal(err)
		}
		verifier, ok := any(restarted).(apikey.AtomicVerifier)
		if !ok {
			t.Fatal("native API-key backend does not implement its public AtomicVerifier contract")
		}
		out, err := verifier.VerifyAndConsume(ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: create.Authentication.TenantID, ConfigurationID: c.Configuration.Spec().ID, ConfigurationRevision: c.Configuration.Spec().Revision, Secret: secret, RequiredPermissions: []string{"invoice.read"}})
		if allowed && (err != nil || out.Result == nil) {
			t.Fatal("active rotated successor denied", err)
		}
		if !allowed && (!errors.Is(err, apikey.ErrDenied) || out.Result != nil) {
			t.Fatalf("terminal predecessor/successor denial failed: error_type=%T principal=%t outcome=%d state=%d", err, out.Result != nil, out.Outcome, out.State)
		}
	}
	verify(oldWire, false)
	verify(newWire, true)
	revoke := apikey.Revocation{Authentication: create.Authentication, IdempotencyKey: key("revocation-original-request"), KeyID: after.ID, ExpectedVersion: after.Version, CorrelationID: "native-revocation", Network: create.Network}
	revokeRollback := revoke
	revokeRollback.IdempotencyKey = key("revocation-required-audit-rollback")
	rejectMutationAudit(t, ctx, pool, "identity.api_key.revoke", func() {
		out, err := restarted.Revoke(ctx, revokeRollback)
		if err == nil || out.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("revocation survived required audit failure")
		}
	})
	assertStoredKeyState(t, ctx, pool, create.Authentication.TenantID, after.ID, apikey.KeyActive, after.Version, after.AuthorityVersion)
	verify(newWire, true)
	revoked, err := restarted.Revoke(ctx, revoke)
	if err != nil || revoked.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native successor revocation failed", err)
	}
	verify(newWire, false)
	revokedAgain, err := restarted.Revoke(ctx, revoke)
	if err != nil || revokedAgain.Binding != revoked.Binding || revokedAgain.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("revocation retry changed original transition", err)
	}
	var tombstones int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id IN ($2,$3)`, string(create.Authentication.TenantID), string(before.ID), string(after.ID)).Scan(&tombstones); err != nil || tombstones != 2 {
		t.Fatal("rotation/revocation deleted terminal evidence")
	}
	assertStoredKeyState(t, ctx, pool, create.Authentication.TenantID, before.ID, apikey.KeyRevoked, before.Version+1, before.AuthorityVersion+1)
	assertStoredKeyState(t, ctx, pool, create.Authentication.TenantID, after.ID, apikey.KeyRevoked, after.Version+1, after.AuthorityVersion+1)
	create.IdempotencyKey = key("rotation-revocation-contention-create")
	contended, err := s.Create(ctx, create)
	if err != nil {
		t.Fatal("contention issuance failed", err)
	}
	source, ok := contended.Record()
	if !ok {
		t.Fatal("contention source missing")
	}
	rotation := request
	rotation.KeyID, rotation.ExpectedVersion, rotation.IdempotencyKey = source.ID, source.Version, key("rotation-contention")
	deletion := apikey.Revocation(rotation)
	deletion.IdempotencyKey = key("revocation-contention")
	type outcome struct {
		receipt   identity.CommandResult
		err       error
		successor *apikey.Record
	}
	results := make(chan outcome, 2)
	start := make(chan struct{})
	var group sync.WaitGroup
	group.Go(func() {
		<-start
		out, err := s.Rotate(ctx, rotation)
		receipt, _ := out.Receipt()
		var successor *apikey.Record
		if r, ok := out.Record(); ok {
			successor = &r
		}
		results <- outcome{receipt, err, successor}
	})
	group.Go(func() { <-start; receipt, err := s.Revoke(ctx, deletion); results <- outcome{receipt, err, nil} })
	close(start)
	group.Wait()
	close(results)
	committed := 0
	for result := range results {
		if result.receipt.Outcome == identity.CommitOutcomeCommitted {
			if result.err != nil {
				t.Fatal("committed contender returned an execution error", result.err)
			}
			committed++
			if result.successor != nil {
				assertStoredKeyState(t, ctx, pool, create.Authentication.TenantID, result.successor.ID, apikey.KeyActive, 1, 1)
			}
		} else {
			var conflict identity.ConflictError
			if !errors.Is(result.err, apikey.ErrDenied) && !errors.As(result.err, &conflict) {
				t.Fatal("losing contender lost its known noncommit disposition", result.err)
			}
		}
	}
	if committed != 1 {
		t.Fatal("rotate/revoke contention committed more or fewer than one source transition")
	}
	assertStoredKeyState(t, ctx, pool, create.Authentication.TenantID, source.ID, apikey.KeyRevoked, source.Version+1, source.AuthorityVersion+1)
}

// This is an infrastructure fault injected after the real participant's domain
// writes, at its required audit owner's persistence boundary. No substitute
// transaction or audit implementation participates in the operation.
func rejectMutationAudit(t *testing.T, ctx context.Context, pool *database.Pool, action string, operation func()) {
	t.Helper()
	if action != "identity.api_key.create" && action != "identity.api_key.rotate" && action != "identity.api_key.revoke" && action != "identity.api_key.update" && action != "identity.api_key.import" {
		t.Fatal("invalid fault action")
	}
	_, err := pool.Raw().Exec(ctx, `CREATE FUNCTION public.reject_api_key_mutation_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = '`+action+`' THEN RAISE EXCEPTION 'injected required audit outage'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_api_key_mutation_audit BEFORE INSERT ON audit.records FOR EACH ROW EXECUTE FUNCTION public.reject_api_key_mutation_audit()`)
	if err != nil {
		t.Fatal("required-audit fault setup failed", err)
	}
	defer func() {
		if _, err := pool.Raw().Exec(ctx, `DROP TRIGGER reject_api_key_mutation_audit ON audit.records; DROP FUNCTION public.reject_api_key_mutation_audit()`); err != nil {
			t.Error("required-audit fault cleanup failed", err)
		}
	}()
	operation()
}

func assertStoredKeyState(t *testing.T, ctx context.Context, pool *database.Pool, tenant identity.TenantID, id apikey.KeyID, status apikey.KeyStatus, version, authority uint64) {
	t.Helper()
	var wire []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, string(tenant), string(id)).Scan(&wire); err != nil {
		t.Fatal("key state missing", err)
	}
	var record struct {
		Status                                 apikey.KeyStatus
		Version, AuthorityVersion, RootVersion uint64
		Grant                                  []string
	}
	if json.Unmarshal(wire, &record) != nil || record.Status != status || record.Version != version || record.AuthorityVersion != authority || record.RootVersion != authority || status == apikey.KeyRevoked && len(record.Grant) != 0 {
		t.Fatal("key transition lost exact CAS/security root or terminal deny-all state")
	}
}

// This continues the same genuine public signup/signin journey. Native secret
// comparison, current owner/tenant/policy reads and SQL are never mocked.
func exerciseAtomicVerification(t *testing.T, ctx context.Context, pool *database.Pool, s *apikeypg.Service, c apikeypg.ServiceConfig, create apikey.CreateRequest, wire string, issued apikey.Record, deniedGrant *atomic.Bool) {
	t.Helper()
	verifier, ok := any(s).(apikey.AtomicVerifier)
	if !ok {
		t.Fatal("native API-key backend does not implement its public AtomicVerifier contract")
	}
	secret, err := apikey.ParseSecret(wire)
	if err != nil {
		t.Fatal("original modern key could not be presented")
	}
	request := apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(commandID(t)), TenantID: create.Authentication.TenantID, ConfigurationID: c.Configuration.Spec().ID, ConfigurationRevision: c.Configuration.Spec().Revision, Secret: secret, RequiredPermissions: []string{"invoice.read"}}
	verified, err := verifier.VerifyAndConsume(ctx, request)
	if err != nil || verified.Validate() != nil || verified.State != apikey.VerificationAttemptNotApplicable || verified.Outcome != identity.CommitOutcomeCommitted || verified.Result == nil || verified.Result.ValidateAt(c.Configuration, time.Now()) != nil {
		t.Fatal("fresh native service failed real unlimited API-key verification", err)
	}
	budget := c.Configuration.Spec().ClockUncertainty + c.Configuration.Spec().DecisionRaceBudget
	if verified.Result.ValidUntil.Nanosecond()%1000 != 0 || verified.Result.ValidUntil.After(verified.Result.ReadStartedAt.Add(20*time.Second-budget)) {
		t.Fatal("fractional-budget canonicalization extended or corrupted original validity")
	}
	if verified.Original.CommandID != identity.CommandID(request.AttemptID) || verified.Original.TenantID != request.TenantID || verified.Original.UserID != issued.Owner.Spec().UserID || verified.Original.ActorKind != authorization.SubjectAPIKey || string(verified.Original.ActorID) != string(issued.ID) || verified.Result.Record.ID != issued.ID || verified.Result.Record.Version != issued.Version || verified.Result.Record.RootID != issued.RootID || verified.Result.Record.RootVersion != issued.RootVersion || verified.Result.ConfigurationAuthority.Version != 1 {
		t.Fatal("verification impersonated a human, rewrote a key root or substituted the configuration epoch")
	}
	replay, err := verifier.VerifyAndConsume(ctx, request)
	if err != nil || replay.Validate() != nil || replay.Fingerprint != verified.Fingerprint || replay.Original != verified.Original || replay.Result == nil || !replay.Result.ReadStartedAt.Equal(verified.Result.ReadStartedAt) || !replay.Result.VerifiedAt.Equal(verified.Result.VerifiedAt) || !replay.Result.ValidUntil.Equal(verified.Result.ValidUntil) {
		t.Fatal("exact attempt replay reauthenticated or renewed its original evidence", err)
	}
	statusOnly, err := verifier.ReconcileVerifyAndConsume(ctx, apikey.VerificationReconcileQuery{AttemptID: verified.AttemptID, TenantID: request.TenantID, Fingerprint: verified.Fingerprint, Original: verified.Original})
	if err != nil || statusOnly.Fingerprint != verified.Fingerprint || statusOnly.Original != verified.Original || statusOnly.Result == nil || !statusOnly.Result.ValidUntil.Equal(verified.Result.ValidUntil) {
		t.Fatal("raw-free reconciliation changed original routing or renewed evidence", err)
	}
	changed := request
	changed.RequiredPermissions = []string{"invoice.write"}
	conflicted, err := verifier.VerifyAndConsume(ctx, changed)
	var conflict identity.ConflictError
	if !errors.As(err, &conflict) || conflicted.Result != nil || conflicted.State != apikey.VerificationAttemptNotDebited {
		t.Fatal("same attempt accepted a changed canonical request")
	}
	wrongSecret, err := apikey.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	changedSecret := request
	changedSecret.Secret = wrongSecret
	changedResult, changedErr := verifier.VerifyAndConsume(ctx, changedSecret)
	if !errors.As(changedErr, &conflict) || changedResult.Result != nil || changedResult.Fingerprint != ([32]byte{}) {
		t.Fatal("changed secret reused a committed attempt or disclosed its original commitment", changedErr)
	}
	wrong := request
	wrong.AttemptID = apikey.VerificationAttemptID(commandID(t))
	wrong.Secret = wrongSecret
	denied, err := verifier.VerifyAndConsume(ctx, wrong)
	if !errors.Is(err, apikey.ErrDenied) || denied.Validate() != nil || denied.Result != nil || denied.State != apikey.VerificationAttemptNotDebited || denied.Outcome != identity.CommitOutcomeCommitted || denied.Original.UserID != "" || denied.Original.AnonymousFlowID != string(wrong.AttemptID) || denied.Original.ActorKind != authorization.SubjectServiceAccount {
		t.Fatal("unknown key denial was not durably recorded in its real anonymous namespace")
	}
	assertAttemptAudit(t, ctx, pool, denied.Original.CommandID, "identity.api_key.authenticate", audit.OutcomeDenied)
	unknownReplay, err := verifier.VerifyAndConsume(ctx, wrong)
	if !errors.Is(err, apikey.ErrDenied) || unknownReplay.Fingerprint != denied.Fingerprint || unknownReplay.Original != denied.Original || unknownReplay.Result != nil {
		t.Fatal("recorded unknown-key denial was reinterpreted on retry")
	}
	deniedStatus, err := verifier.ReconcileVerifyAndConsume(ctx, apikey.VerificationReconcileQuery{AttemptID: denied.AttemptID, TenantID: wrong.TenantID, Fingerprint: denied.Fingerprint, Original: denied.Original})
	if !errors.Is(err, apikey.ErrDenied) || deniedStatus.Fingerprint != denied.Fingerprint || deniedStatus.Original != denied.Original || deniedStatus.Result != nil {
		t.Fatal("unknown-key reconciliation fabricated a user or principal")
	}
	foreign := request
	foreign.AttemptID = apikey.VerificationAttemptID(commandID(t))
	foreign.TenantID = "unrelated-tenant"
	foreignResult, err := verifier.VerifyAndConsume(ctx, foreign)
	if !errors.Is(err, apikey.ErrDenied) || foreignResult.Result != nil {
		t.Fatal("correct raw key authenticated another tenant")
	}
	foreign = request
	foreign.AttemptID = apikey.VerificationAttemptID(commandID(t))
	foreign.ConfigurationID = "other-configuration"
	foreignResult, err = verifier.VerifyAndConsume(ctx, foreign)
	if err == nil || foreignResult.Result != nil {
		t.Fatal("raw key selected another server-owned configuration")
	}
	// A second credential shares configuration evidence, not the first key's
	// root or immutable grant. Configuration advancement must not rewrite it.
	secondRequest := create
	secondRequest.Name = "independent-automation"
	secondRequest.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("api-key-consumer-second-create"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Create(ctx, secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	secondRecord, ok := second.Record()
	if !ok {
		t.Fatal("second independent credential missing")
	}
	secondWire, err := second.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secondSecret, err := apikey.ParseSecret(secondWire)
	if err != nil {
		t.Fatal(err)
	}
	deniedGrant.Store(true)
	advanceUserPolicy(t, ctx, pool, c.Profile.PolicyNamespace, issued.Owner.Spec().UserID)
	knownWrong := wrong
	knownWrong.AttemptID = apikey.VerificationAttemptID(commandID(t))
	knownWrong.Candidate = issued.ID
	var before, after []byte
	if err := pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, string(request.TenantID), string(issued.ID)).Scan(&before); err != nil {
		t.Fatal("known-candidate comparison precondition missing", err)
	}
	mismatch, err := verifier.VerifyAndConsume(ctx, knownWrong)
	if !errors.Is(err, apikey.ErrDenied) || mismatch.Validate() != nil || mismatch.Result != nil || mismatch.State != apikey.VerificationAttemptNotDebited || mismatch.Outcome != identity.CommitOutcomeCommitted || mismatch.Original.UserID != issued.Owner.Spec().UserID || mismatch.Original.ActorKind != authorization.SubjectAPIKey {
		t.Fatal("existing candidate authenticated a different valid secret", err)
	}
	if err := pool.Raw().QueryRow(ctx, `SELECT record FROM identity_api_keys.keys WHERE tenant_id=$1 AND key_id=$2`, string(request.TenantID), string(issued.ID)).Scan(&after); err != nil || !bytes.Equal(before, after) {
		t.Fatal("wrong secret narrowed the known candidate's durable grant or versions", err)
	}
	assertAttemptAudit(t, ctx, pool, mismatch.Original.CommandID, "identity.api_key.authenticate", audit.OutcomeDenied)
	mismatchCommand, err := base64.RawURLEncoding.Strict().DecodeString(string(mismatch.Original.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var mutationEffects int
	if err := pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND b.command_id=$2 AND r.action='identity.api_key.update') +
 (SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$2 AND m.topic IN ('api_key.permissions_changed.v1','api_key.revoked.v1'))`, string(request.TenantID), mismatchCommand).Scan(&mutationEffects); err != nil || mutationEffects != 0 {
		t.Fatal("wrong secret committed Narrow or revocation effects", err)
	}
	removed := request
	removed.AttemptID = apikey.VerificationAttemptID(commandID(t))
	removed.RequiredPermissions = []string{"invoice.write"}
	rollback := removed
	rollback.AttemptID = apikey.VerificationAttemptID(commandID(t))
	var failedOriginal apikey.AtomicVerificationResult
	rejectMutationAudit(t, ctx, pool, "identity.api_key.update", func() {
		failed, err := verifier.VerifyAndConsume(ctx, rollback)
		if err == nil || failed.Validate() != nil || failed.Result != nil || failed.State != apikey.VerificationAttemptNotDebited || failed.Outcome == identity.CommitOutcomeCommitted {
			t.Fatal("failed required Narrow audit disclosed authentication or commitment", err)
		}
		failedOriginal = failed
	})
	assertStoredKeyState(t, ctx, pool, request.TenantID, issued.ID, apikey.KeyActive, issued.Version, issued.AuthorityVersion)
	var unchangedConfiguration int
	if err := pool.Raw().QueryRow(ctx, `SELECT authority_version FROM identity_api_keys.configurations WHERE tenant_id=$1 AND configuration_id=$2`, string(request.TenantID), request.ConfigurationID).Scan(&unchangedConfiguration); err != nil || unchangedConfiguration != 1 {
		t.Fatal("required Narrow audit failure advanced configuration authority", err)
	}
	narrowedDenial, err := verifier.VerifyAndConsume(ctx, removed)
	deniedGrant.Store(false)
	advanceUserPolicy(t, ctx, pool, c.Profile.PolicyNamespace, issued.Owner.Spec().UserID)
	if !errors.Is(err, apikey.ErrDenied) || narrowedDenial.Result != nil || narrowedDenial.State != apikey.VerificationAttemptNotDebited || narrowedDenial.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("removed permission authenticated or its Narrow/attempt did not commit")
	}
	assertAttemptAudit(t, ctx, pool, narrowedDenial.Original.CommandID, "identity.api_key.authenticate", audit.OutcomeDenied)
	assertAttemptAudit(t, ctx, pool, narrowedDenial.Original.CommandID, "identity.api_key.update", audit.OutcomeSucceeded)
	failedReplay, failedErr := verifier.VerifyAndConsume(ctx, rollback)
	var failedConflict identity.ConflictError
	if errors.As(failedErr, &failedConflict) || failedReplay.Validate() != nil || failedReplay.Outcome != failedOriginal.Outcome || failedReplay.Fingerprint != failedOriginal.Fingerprint || failedReplay.Original != failedOriginal.Original || failedReplay.Result != nil || failedReplay.State != apikey.VerificationAttemptNotDebited {
		t.Fatal("identical failed attempt lost its original disposition after an independent key transition", failedOriginal.Outcome, failedReplay.Outcome, failedErr)
	}
	originalRetry, retryErr := verifier.VerifyAndConsume(ctx, request)
	if originalRetry.Outcome != identity.CommitOutcomeCommitted || originalRetry.Fingerprint != verified.Fingerprint || originalRetry.Original != verified.Original || retryErr != nil && !errors.Is(retryErr, apikey.ErrDenied) || originalRetry.Result != nil && (!originalRetry.Result.ValidUntil.Equal(verified.Result.ValidUntil) || !originalRetry.Result.ReadStartedAt.Equal(verified.Result.ReadStartedAt) || originalRetry.Result.Record.Version != verified.Result.Record.Version) {
		t.Fatal("exact original retry was reinterpreted after key version changed", retryErr)
	}
	narrowCommand, err := base64.RawURLEncoding.Strict().DecodeString(string(narrowedDenial.Original.CommandID))
	if err != nil {
		t.Fatal(err)
	}
	var lifecycle int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.identity_outbox_bindings b JOIN public.outbox_messages m ON m.id=b.effect_id WHERE b.tenant_id=$1 AND b.command_id=$2 AND m.topic='api_key.permissions_changed.v1' AND convert_from(m.payload,'UTF8')::jsonb->>'subject_id'=$3`, string(request.TenantID), narrowCommand, string(issued.ID)).Scan(&lifecycle); err != nil || lifecycle != 1 {
		t.Fatal("Narrow lifecycle did not bind the actual key in the same original command")
	}
	read := request
	read.AttemptID = apikey.VerificationAttemptID(commandID(t))
	narrowed, err := verifier.VerifyAndConsume(ctx, read)
	if err != nil || narrowed.Result == nil || len(narrowed.Result.Record.Grant) != 1 || narrowed.Result.Record.Grant[0] != "invoice.read" || narrowed.Result.Record.Version != issued.Version+1 || narrowed.Result.Record.AuthorityVersion != issued.AuthorityVersion+1 || narrowed.Result.Record.RootVersion != issued.RootVersion+1 || narrowed.Result.ConfigurationAuthority.Version != 2 {
		t.Fatal("actual current intersection/root/configuration successor was not persisted", err)
	}
	// Restoring external policy never expands the now-persisted key ceiling.
	removed.AttemptID = apikey.VerificationAttemptID(commandID(t))
	stillDenied, err := verifier.VerifyAndConsume(ctx, removed)
	if !errors.Is(err, apikey.ErrDenied) || stillDenied.Result != nil {
		t.Fatal("policy restoration expanded the immutable narrowed key grant")
	}
	read.AttemptID = apikey.VerificationAttemptID(commandID(t))
	read.Secret = secondSecret
	independent, err := verifier.VerifyAndConsume(ctx, read)
	if err != nil || independent.Result == nil || independent.Result.Record.ID != secondRecord.ID || independent.Result.Record.Version != secondRecord.Version || independent.Result.Record.RootVersion != secondRecord.RootVersion || independent.Result.ConfigurationAuthority.Version != 2 {
		t.Fatal("configuration epoch advancement rewrote the second credential root", err)
	}
	var attempts int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity_api_keys.command_effects WHERE tenant_id=$1 AND command_id=$2 AND fingerprint=$3`, string(request.TenantID), string(request.AttemptID), verified.Fingerprint[:]).Scan(&attempts); err != nil || attempts != 1 {
		t.Fatal("exact successful attempt/fingerprint was not durably unique")
	}
	t.Run("expired-original-is-history-not-authentication", func(t *testing.T) {
		// Expiry itself is the contract: wait for this actual original deadline,
		// never alter stored evidence or replace the primary database clock.
		remaining := time.Until(verified.Result.ValidUntil)
		if remaining > 20*time.Second {
			t.Fatal("original validity exceeded its bounded authority window")
		}
		timer := time.NewTimer(max(remaining, 0) + time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			t.Fatal("original-expiry observation exceeded fixture deadline")
		case <-timer.C:
		}
		expired, err := verifier.VerifyAndConsume(ctx, request)
		if !errors.Is(err, apikey.ErrDenied) || expired.Validate() != nil || expired.Outcome != identity.CommitOutcomeCommitted || expired.Result != nil || expired.Fingerprint != verified.Fingerprint || expired.Original != verified.Original {
			t.Fatal("expired original replay renewed authority or erased commitment", err)
		}
		history, err := verifier.ReconcileVerifyAndConsume(ctx, apikey.VerificationReconcileQuery{AttemptID: verified.AttemptID, TenantID: request.TenantID, Fingerprint: verified.Fingerprint, Original: verified.Original})
		if !errors.Is(err, apikey.ErrDenied) || history.Validate() != nil || history.Outcome != identity.CommitOutcomeCommitted || history.Result != nil || history.Fingerprint != verified.Fingerprint || history.Original != verified.Original {
			t.Fatal("expired original inquiry reauthenticated or erased commitment", err)
		}
	})
	// This infrastructure probe only withdraws an already genuine user's
	// primary authority. It creates no identity/credential and never restores
	// positive authority. The status owner's dual-version rule is defined in
	// identity/postgres StatusUnitOfWork; its admin/cascade workflow is not
	// exercised or declared complete by this API-key consumer.
	withdrawn, err := pool.Raw().Exec(ctx, `UPDATE identity.users SET status='suspended',version=version+1,authority_version=authority_version+1 WHERE tenant_id=$1 AND user_id=$2 AND status='active'`, string(request.TenantID), string(issued.Owner.Spec().UserID))
	if err != nil || withdrawn.RowsAffected() != 1 {
		t.Fatal("primary owner-authority withdrawal probe failed", err)
	}
	read.AttemptID = apikey.VerificationAttemptID(commandID(t))
	blocked, err := verifier.VerifyAndConsume(ctx, read)
	if err == nil || blocked.Validate() != nil || blocked.Result != nil || blocked.State != apikey.VerificationAttemptNotDebited {
		t.Fatal("fresh verification escaped suspended primary owner authority", err)
	}
}

func assertAttemptAudit(t *testing.T, ctx context.Context, pool *database.Pool, id identity.CommandID, action string, outcome audit.Outcome) {
	t.Helper()
	command, err := base64.RawURLEncoding.Strict().DecodeString(string(id))
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM audit.identity_command_bindings b JOIN audit.records r ON r.record_id=b.event_id WHERE b.tenant_id=$1 AND b.command_id=$2 AND r.action=$3 AND r.outcome=$4`, baselineTenant, command, action, int16(outcome)).Scan(&count); err != nil || count != 1 {
		t.Fatal("durable attempt audit reported the wrong security outcome")
	}
}

// Controlled external entitlement change uses the real public authorization
// epoch owner. It is test setup, not an invented identity authority or an admin
// workflow under test. Native key verification must observe its current epoch
// without depending on the human's now-stale password-session snapshot.
func advanceUserPolicy(t *testing.T, ctx context.Context, pool *database.Pool, namespace string, user identity.UserID) {
	t.Helper()
	store, err := authority.NewAuthorityStore(pool.Raw(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	scope := authority.AuthorityScope{TenantID: baselineTenant, PolicyNamespace: namespace, SubjectID: authorization.SubjectID(user)}
	before, err := store.Get(ctx, scope)
	if err != nil {
		t.Fatal("actual policy authority missing", err)
	}
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	after, err := authority.AdvanceAuthority(ctx, tx, scope, before.Version, time.Second)
	if err != nil || after.Version != before.Version+1 {
		t.Fatal("actual policy epoch did not advance", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal("actual policy authority change not committed")
	}
}
