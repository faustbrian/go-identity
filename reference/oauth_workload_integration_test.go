//go:build integration

package reference_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	password "github.com/faustbrian/go-password/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type referenceWorkloadPolicy struct{}

func (referenceWorkloadPolicy) Evaluate(ctx context.Context, r authorization.Request) (authorization.Decision, error) {
	d := authorization.Decision{Outcome: authorization.Deny}
	if err := ctx.Err(); err != nil {
		return d, err
	}
	_, flowErr := identity.ParseCommandID(string(r.Resource.ID))
	if r.Tenant == otpTenant && r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "oauth-worker" && r.Resource.Type == "identity.anonymous-flow" && flowErr == nil {
		switch r.Action {
		case "identity.oauth-server.token", "identity.oauth-server.token.recover", "identity.oauth-server.revoke", "identity.oauth-server.revoke.recover":
			d.Outcome = authorization.Allow
		}
	}
	return d, nil
}

func referenceWorkloadConfiguration(t *testing.T, c reference.StoreConfiguration, origin string) (reference.StoreConfiguration, reference.ReferenceDependencies, identity.PolicySet, string) {
	t.Helper()
	keys := make(map[string][32]byte)
	for _, name := range []string{"fingerprint", "request", "evidence", "seal", "token", "intent", "envelope", "counter-envelope", "http", "migration"} {
		var value [32]byte
		if _, err := rand.Read(value[:]); err != nil {
			t.Fatal("fixture entropy unavailable")
		}
		keys[name] = value
	}
	t.Cleanup(func() { clear(keys) })
	material := func(name string) []byte { k := keys[name]; return append([]byte(nil), k[:]...) }
	issuer, err := oauth.NewIssuer(origin)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := oauth.NewPlatformOwner("deployment")
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := oauth.NewScopeCatalog([]string{"workload:read", "workload:write"})
	if err != nil {
		t.Fatal(err)
	}
	workload, err := oauth.NewWorkload(otpTenant, "oauth-worker", 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client := oauth.Client{ID: "reference-machine", Owner: owner, Version: 1, AuthenticationMethod: "client_secret_basic", Resource: "https://resource.example", Scopes: scopes.Scopes(), Workload: workload}
	token, err := oauth.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	secret, err := password.NewSecret([]byte(wire))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := oauth.NewClientSecretVerifier(client.ID, client.Version, secret)
	secret.Destroy()
	if err != nil {
		t.Fatal(err)
	}
	protocol := oauth.Config{Issuer: issuer, Environment: "reference-workload", Resource: client.Resource, Scopes: scopes, Clients: []oauth.Client{client}, ClientSecrets: []oauth.ClientSecretVerifier{verifier}, OwningClientIntrospection: true,
		Discovery: oauth.DiscoveryConfig{Enabled: true, TokenEndpoint: origin + "/oauth2/token", RevocationEndpoint: origin + "/oauth2/revoke", IntrospectionEndpoint: origin + "/oauth2/introspect"},
		Clock:     clock.System{}, MaximumDuration: 4 * time.Second, CodeTTL: time.Minute, ContinuationTTL: time.Minute, AccessTTL: time.Minute, RefreshTTL: time.Hour}
	snapshot, err := authorization.NewSnapshot(3, authorization.DenyOverrides, authorization.PolicyDefinition{ID: "reference-workload", Revision: 3, Evaluator: referenceWorkloadPolicy{}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := authorization.NewEngine(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	decisions, err := authorization.NewDecisionService(engine)
	if err != nil {
		t.Fatal(err)
	}
	query := kernel.CommandQueryPolicy{Clock: clock.System{}, Authorization: decisions, PolicyVersion: 3}
	coordinator := kernel.CoordinatorConfig{MaximumDuration: 4 * time.Second, LeaseDuration: 5 * time.Second, CurrentFingerprintKeyVersion: 1, RetainedFingerprintKeys: map[uint32][32]byte{1: keys["fingerprint"]}, QueryPolicy: &query, AdmissionPolicy: &query}
	requestKeys, err := kernel.NewRequestKeyConfig("reference-oauth", keys["request"], query)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := risk.NewEvidenceKey(1, material("evidence"), material("seal"))
	if err != nil {
		t.Fatal(err)
	}
	tokenKey, err := oauth.NewTokenDigestKey(1, material("token"))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := keyring.New(map[string][]byte{"envelope": material("envelope")})
	if err != nil {
		t.Fatal(err)
	}
	protected := riskpg.Config{Schema: c.Velocity.Schema, PolicyVersion: 3, EvidenceKeys: []risk.EvidenceKey{evidence}, EnvelopeKeys: map[string][]byte{"counter": material("counter-envelope")}, CurrentEnvelopeKey: "counter", CommandCounters: &risk.CommandCounterPolicyConfig{Policy: c.Velocity.Native.Policy, Keys: c.Velocity.Native.Keys}, EnforceLockouts: true}
	c.Velocity.Tenants = []string{otpTenant}
	selectDurableReferenceAdmission(&c)
	c.DurableAdmission.Timeout = 5 * time.Second
	c.OAuthWorkload = &reference.OAuthWorkloadConfiguration{Protocol: protocol, Schema: "oauth_store", GlobalAuthorityID: "deployment", PolicyNamespace: "oauth-workloads", BootstrapTenantIDs: []identity.TenantID{otpTenant}, TokenKeys: []oauth.TokenDigestKey{tokenKey}, ActiveTokenKeyVersion: 1, IntentKey: keys["intent"], ActiveEnvelopeKeyID: "envelope", Coordinator: coordinator, RequestKeys: requestKeys, PolicyID: "reference-oauth", Counters: protected}
	c.HTTPOAuthWorkload = &reference.HTTPOAuthWorkloadConfiguration{Token: true, Introspect: true, Revoke: true, Namespace: "reference-oauth"}
	c.HTTPRate = &reference.HTTPRateConfiguration{Namespace: "reference-http", IdentifierKey: keys["http"], MaximumDuration: time.Second, Timeout: time.Second, LockTimeout: 500 * time.Millisecond, RollbackTimeout: 500 * time.Millisecond}
	c.Migrations = &reference.MigrationApplyPolicy{TenantID: otpTenant, ActorID: "operator", LookupKey: keys["migration"], LockTimeout: time.Second, CleanupTimeout: time.Second}
	policies := identity.PolicySet{Authorize: decisions,
		AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) {
			return identity.RiskPolicyDecision{}, identity.UnavailableError{}
		},
		MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			return identity.ClaimsPolicyDecision{}, identity.UnavailableError{}
		},
		DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			return identity.RetentionPolicyDecision{}, identity.UnavailableError{}
		},
		Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			return identity.RedactionPolicyDecision{}, identity.UnavailableError{}
		}}
	return c, reference.ReferenceDependencies{EnvelopeKeys: provider}, policies, wire
}

func referenceWorkloadServerConfig(policies identity.PolicySet) reference.ReferenceConfig {
	return reference.ReferenceConfig{Profile: reference.PostgresOnly, Policies: policies, HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 8192, MaximumURLBytes: 4096, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 16, MaximumDepth: 2}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}}, HandlerTimeout: 4 * time.Second, Document: identityhttp.DocumentConfig{Title: "Workload reference", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: time.Second}, Tenant: reference.TenantPolicy{Resolver: &nativeServerTenant{}}}
}

// The public graph owns every migration, native service and handler. The
// consumer supplies only deployment configuration, credentials and policy.
func TestReferencePostgresOAuthWorkloadHTTPS(t *testing.T) {
	for _, populated := range []bool{false, true} {
		t.Run(map[bool]string{false: "fresh", true: "populated-prefix"}[populated], func(t *testing.T) {
			proveReferenceOAuthWorkload(t, populated)
		})
	}
}

func proveReferenceOAuthWorkload(t *testing.T, populated bool) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	network := httptest.NewUnstartedServer(nil)
	t.Cleanup(network.Close)
	origin := "https://" + network.Listener.Addr().String()
	c, deps, policies, secret := referenceWorkloadConfiguration(t, f.config, origin)
	deps.PostgreSQL = f.pool
	if populated {
		baseConfig := c
		baseConfig.OAuthWorkload, baseConfig.HTTPOAuthWorkload = nil, nil
		base, err := reference.ComposeStores(baseConfig, reference.ReferenceDependencies{PostgreSQL: f.pool})
		if err != nil {
			t.Fatal("existing storage-only profile", err)
		}
		defer func() {
			bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := base.Close(bounded); err != nil {
				t.Error(err)
			}
		}()
		before, err := base.MigrationSource().Load(ctx)
		if err != nil {
			t.Fatal(err)
		}
		original := applyRequest(t, ctx, base, []reference.ModuleID{"identity/postgres", "identity/risk/postgres"})
		if out, err := base.ReferenceMigrationApply(ctx, original); err != nil || out.Result.State() != reference.MigrationApplied {
			t.Fatal("existing native prefix", err)
		}
		selected, err := reference.ComposeStores(c, deps)
		if err != nil {
			t.Fatal(err)
		}
		after, err := selected.MigrationSource().Load(ctx)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("workload selection rewrote existing shared history", err)
		}
		if err := selected.Close(ctx); err != nil {
			t.Fatal(err)
		}
	}
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("workload-only stores", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	config := referenceWorkloadServerConfig(policies)
	server, err := reference.NewServer(config, deps, features)
	if err != nil {
		t.Fatal("workload-only server", err)
	}
	if server.Readiness(ctx).Ready {
		t.Fatal("uninitialized graph ready")
	}
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "oauth-server/postgres"}
	request := applyRequest(t, ctx, stores, modules)
	if populated {
		request.CommandID = "migration_oauth_forward_0002"
		var retry [32]byte
		if _, err := rand.Read(retry[:]); err != nil {
			t.Fatal(err)
		}
		request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte(base64.RawURLEncoding.EncodeToString(retry[:])))
		if err != nil {
			t.Fatal(err)
		}
	}
	if out, err := stores.ReferenceMigrationApply(ctx, request); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("owned workload migrations", err)
	}
	// The successful fresh audit install creates cluster-wide roles, unlike
	// this test's disposable database. Release only those just-created roles.
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(bounded, "DROP OWNED BY audit_writer,audit_reader,audit_retention; DROP ROLE audit_writer,audit_reader,audit_retention"); err != nil {
			t.Error("owned workload audit role cleanup", err)
		}
	})
	if err := stores.BootstrapOAuthWorkloads(ctx); err != nil {
		t.Fatal("explicit workload authority bootstrap", err)
	}
	if !populated {
		var otherKey [32]byte
		if _, err := rand.Read(otherKey[:]); err != nil {
			t.Fatal(err)
		}
		wrongKeys, err := keyring.New(map[string][]byte{"unselected-key": otherKey[:]})
		clear(otherKey[:])
		if err != nil {
			t.Fatal(err)
		}
		wrongDeps := deps
		wrongDeps.EnvelopeKeys = wrongKeys
		wrong, err := reference.ComposeStores(c, wrongDeps)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := wrong.Close(bounded); err != nil {
				t.Error(err)
			}
		})
		wp, err := reference.ComposeProviders(wrong)
		if err != nil {
			t.Fatal(err)
		}
		ww, err := reference.ComposeWorkers(wrong, wp)
		if err != nil {
			t.Fatal(err)
		}
		wf, err := reference.ComposeFeatures(wrong, wp, ww)
		if err != nil {
			t.Fatal(err)
		}
		ws, err := reference.NewServer(config, wrongDeps, wf)
		if err != nil {
			t.Fatal(err)
		}
		if err := wf.Initialize(ctx); err == nil {
			t.Fatal("missing selected envelope key initialized successfully")
		}
		if ws.Readiness(ctx).Ready {
			t.Fatal("missing selected envelope key reported ready")
		}
	}
	if err := features.Initialize(ctx); err != nil {
		t.Fatal("workload initialization", err)
	}
	if !server.Readiness(ctx).Ready {
		t.Fatal("initialized selected graph not ready")
	}
	for _, table := range []string{"session_store.sessions", "otp_store.challenges", "identity.delivery_intents"} {
		var present bool
		if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", table).Scan(&present); err != nil || present {
			t.Fatal("unselected human owner installed", table, err)
		}
	}
	// The native OAuth base owns an empty consent table even for workload-only
	// use. No human or consent record may be manufactured to enable this graph.
	for _, table := range []string{"identity.users", "oauth_store.consents"} {
		var count int
		if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 0 {
			t.Fatal("workload bootstrap manufactured human state", table, err)
		}
	}
	var serving atomic.Pointer[reference.Server]
	serving.Store(server)
	network.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serving.Load().Handler().ServeHTTP(w, r) })
	network.Config.ReadHeaderTimeout = 2 * time.Second
	network.Config.ReadTimeout, network.Config.WriteTimeout = 5*time.Second, 5*time.Second
	network.StartTLS()
	client := network.Client()
	client.Timeout = 6 * time.Second
	controlSuccesses, lastStatus := 0, 0
	var controlStarted time.Time
	call := func(action string, form url.Values, expected ...int) map[string]json.RawMessage {
		t.Helper()
		if (action == "introspect" || action == "revoke") && controlStarted.IsZero() {
			if err := f.pool.Raw().QueryRow(ctx, "SELECT clock_timestamp()").Scan(&controlStarted); err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/oauth2/"+action, strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape("reference-machine"), url.QueryEscape(secret))
		res, err := client.Do(req)
		if err != nil {
			t.Fatal("actual HTTPS workload operation", action, err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(io.LimitReader(res.Body, 16385))
		if len(expected) == 0 {
			expected = []int{200}
		}
		if err != nil || len(body) > 16384 || !slices.Contains(expected, res.StatusCode) {
			t.Fatal("workload response", action, res.StatusCode)
		}
		lastStatus = res.StatusCode
		if (action == "introspect" || action == "revoke") && res.StatusCode == 200 {
			controlSuccesses++
		}
		if res.Header.Get("Cache-Control") != "no-store" || strings.Contains(string(body), secret) {
			t.Fatal("workload response custody", action)
		}
		if action == "revoke" && res.StatusCode == 200 {
			if len(body) != 0 {
				t.Fatal("nonempty revocation response")
			}
			return nil
		}
		var out map[string]json.RawMessage
		if json.Unmarshal(body, &out) != nil {
			t.Fatal("invalid workload JSON", action)
		}
		if res.StatusCode != 200 && (out["access_token"] != nil || out["refresh_token"] != nil || out["active"] != nil) {
			t.Fatal("denial disclosed bearer or token metadata")
		}
		return out
	}
	tokenForm := url.Values{"grant_type": {"client_credentials"}, "scope": {"workload:read"}, "resource": {"https://resource.example"}}
	issue := func() string {
		t.Helper()
		issued := call("token", tokenForm)
		var access, kind string
		var lifetime int
		if json.Unmarshal(issued["access_token"], &access) != nil || access == "" || json.Unmarshal(issued["token_type"], &kind) != nil || kind != "Bearer" || json.Unmarshal(issued["expires_in"], &lifetime) != nil || lifetime < 1 || lifetime > 30 || issued["refresh_token"] != nil {
			t.Fatal("expected bounded access-only token")
		}
		return access
	}
	access := issue()
	independent := issue()
	form := url.Values{"token": {access}, "token_type_hint": {"access_token"}}
	active := call("introspect", form)
	if string(active["active"]) != "true" || string(active["client_id"]) != `"reference-machine"` || string(active["scope"]) != `"workload:read"` {
		t.Fatal("active token lost workload binding")
	}
	call("revoke", form)
	inactive := call("introspect", form)
	if len(inactive) != 1 || string(inactive["active"]) != "false" {
		t.Fatal("revoked token is not exactly inactive")
	}
	otherForm := url.Values{"token": {independent}, "token_type_hint": {"access_token"}}
	if out := call("introspect", otherForm); string(out["active"]) != "true" {
		t.Fatal("revocation withdrew an independent token")
	}
	if populated {
		return
	}

	counts := func() [4]int64 {
		t.Helper()
		var n [4]int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM oauth_store.grants),(SELECT count(*) FROM oauth_store.artifacts),(SELECT count(*) FROM oauth_store.effects),(SELECT count(*) FROM audit.records WHERE action='identity.oauth_server.authorize' AND outcome=1)`).Scan(&n[0], &n[1], &n[2], &n[3]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := f.pool.Raw().Exec(ctx, sql); err != nil {
			t.Fatal("owned workload fixture boundary", err)
		}
	}
	// Reopen the same public graph over its retained custody and primary state.
	second, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := second.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	providers2, err := reference.ComposeProviders(second)
	if err != nil {
		t.Fatal(err)
	}
	workers2, err := reference.ComposeWorkers(second, providers2)
	if err != nil {
		t.Fatal(err)
	}
	features2, err := reference.ComposeFeatures(second, providers2, workers2)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := reference.NewServer(config, deps, features2)
	if err != nil {
		t.Fatal(err)
	}
	serving.Store(reopened)
	before := counts()
	call("token", tokenForm, 503)
	if counts() != before || reopened.Readiness(ctx).Ready {
		t.Fatal("uninitialized reopened graph admitted work")
	}
	var conflict identity.ConflictError
	if err := second.BootstrapOAuthWorkloads(ctx); !errors.As(err, &conflict) {
		t.Fatal("restart did not preserve existing authority", err)
	}
	owner, err := features2.OAuthWorkloads()
	if err != nil {
		t.Fatal(err)
	}
	authRequest := httptest.NewRequest(http.MethodPost, origin+"/oauth2/token", nil)
	authRequest.SetBasicAuth(url.QueryEscape("reference-machine"), url.QueryEscape(secret))
	nativeRequest, err := oauth.ParseTokenFormWithClientAuthentication(tokenForm.Encode(), authRequest.Header.Values("Authorization"))
	if err != nil {
		t.Fatal(err)
	}
	nativeRequest.Network = "192.0.2.1"
	if _, err := owner.Token(ctx, nativeRequest); err == nil {
		t.Fatal("retained native handle bypassed initialization")
	}
	if counts() != before {
		t.Fatal("pre-initialization native handle wrote state")
	}
	if err := features2.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if out := call("introspect", otherForm); string(out["active"]) != "true" {
		t.Fatal("reopen lost durable token")
	}
	if !reopened.Readiness(ctx).Ready {
		t.Fatal("reopened graph not ready")
	}
	// The direct handle is a real native service behind the same graph lifetime.
	nativeToken, err := owner.Token(ctx, nativeRequest)
	if err != nil || nativeToken.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native workload issuance", err)
	}
	nativeWire, err := nativeToken.AccessToken.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	if out, err := owner.Introspect(ctx, oauth.IntrospectRequest{ClientID: "reference-machine", Token: nativeWire, ClientAuthentication: nativeRequest.ClientAuthentication}); err != nil || !out.Active {
		t.Fatal("native workload introspection", err)
	}
	if out, err := owner.Revoke(ctx, oauth.RevokeRequest{ClientID: "reference-machine", Token: nativeWire, Network: nativeRequest.Network, ClientAuthentication: nativeRequest.ClientAuthentication}); err != nil || out.Outcome != identity.CommitOutcomeCommitted {
		t.Fatal("native workload revocation", err)
	}
	var revokedBefore, revokedAfter int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_access.revoked.v1'`).Scan(&revokedBefore); err != nil {
		t.Fatal(err)
	}
	call("revoke", form)
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.outbox_messages WHERE topic='oauth_access.revoked.v1'`).Scan(&revokedAfter); err != nil || revokedAfter != revokedBefore {
		t.Fatal("repeated revocation duplicated lifecycle", err)
	}
	tx, err := f.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		bounded, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = tx.Rollback(bounded)
	}()
	if _, err := authority.AdvanceAuthority(ctx, tx, authority.AuthorityScope{TenantID: otpTenant, PolicyNamespace: "oauth-workloads", SubjectID: "oauth-worker"}, 1, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if out := call("introspect", otherForm); len(out) != 1 || string(out["active"]) != "false" {
		t.Fatal("old epoch remained active")
	}
	current := issue()
	currentForm := url.Values{"token": {current}}
	if out := call("introspect", currentForm); string(out["active"]) != "true" {
		t.Fatal("fresh issuance at current epoch denied")
	}
	call("revoke", otherForm)
	before = counts()
	func() {
		exec(`ALTER TABLE oauth_store.effects RENAME TO unavailable_reference_oauth_effects`)
		defer exec(`ALTER TABLE oauth_store.unavailable_reference_oauth_effects RENAME TO effects`)
		if reopened.Readiness(ctx).Ready {
			t.Fatal("missing native effect receipt store reported ready")
		}
		call("token", tokenForm, 503)
	}()
	if counts() != before {
		t.Fatal("missing native effect receipt store left partial success")
	}
	func() {
		exec(`ALTER TABLE public.authorization_subject_authorities RENAME TO unavailable_reference_oauth_authorities`)
		defer exec(`ALTER TABLE public.unavailable_reference_oauth_authorities RENAME TO authorization_subject_authorities`)
		call("token", tokenForm, 503)
		call("introspect", currentForm, 503)
		if reopened.Readiness(ctx).Ready || counts() != before {
			t.Fatal("authority outage admitted work or readiness")
		}
	}()
	func() {
		exec(`ALTER TABLE public.outbox_messages ADD CONSTRAINT reject_reference_workload CHECK(topic<>'grant.created.v1') NOT VALID`)
		defer exec(`ALTER TABLE public.outbox_messages DROP CONSTRAINT reject_reference_workload`)
		call("token", tokenForm, 503)
		if counts() != before {
			t.Fatal("failed required outbox did not roll back all success effects")
		}
	}()
	_ = issue()
	before = counts()
	func() {
		exec(`ALTER TABLE public.rate_limit_states RENAME TO unavailable_reference_oauth_rate`)
		defer exec(`ALTER TABLE public.unavailable_reference_oauth_rate RENAME TO rate_limit_states`)
		call("token", tokenForm, 503)
		// Vary trusted transport attribution at the handler seam. Real HTTPS
		// is proved above; no new address can use a local rate fallback.
		r := httptest.NewRequest(http.MethodPost, origin+"/oauth2/token", strings.NewReader(tokenForm.Encode()))
		r.RequestURI = r.URL.RequestURI()
		r.RemoteAddr = "203.0.113.77:54211"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(url.QueryEscape("reference-machine"), url.QueryEscape(secret))
		w := httptest.NewRecorder()
		reopened.Handler().ServeHTTP(w, r)
		if w.Code != 503 || strings.Contains(w.Body.String(), secret) || strings.Contains(w.Body.String(), "access_token") || counts() != before {
			t.Fatalf("fresh network rate denial status=%d changed_effects=%t", w.Code, counts() != before)
		}
	}()
	// Removing the HTTP selection preserves native startup without advertising
	// any OAuth route or HTTP rate migration requirement.
	nativeOnly := c
	nativeOnly.HTTPOAuthWorkload, nativeOnly.HTTPRate = nil, nil
	third, err := reference.ComposeStores(nativeOnly, deps)
	if err != nil {
		t.Fatal("native-only composition", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := third.Close(bounded); err != nil {
			t.Error(err)
		}
	})
	providers3, err := reference.ComposeProviders(third)
	if err != nil {
		t.Fatal(err)
	}
	workers3, err := reference.ComposeWorkers(third, providers3)
	if err != nil {
		t.Fatal(err)
	}
	features3, err := reference.ComposeFeatures(third, providers3, workers3)
	if err != nil {
		t.Fatal(err)
	}
	nativeServer, err := reference.NewServer(config, deps, features3)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range nativeServer.OpenAPI().Operations() {
		if strings.HasPrefix(op.Record.OperationID, "identity.oauth-server.") {
			t.Fatal("native-only selection advertised HTTP")
		}
	}
	route := httptest.NewRequest(http.MethodPost, origin+"/oauth2/token", nil)
	route.RequestURI = route.URL.RequestURI()
	missing := httptest.NewRecorder()
	nativeServer.Handler().ServeHTTP(missing, route)
	if missing.Code != http.StatusNotFound {
		t.Fatal("native-only selection exposed HTTP route", missing.Code)
	}
	if _, err := third.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"rate-limit/postgres"}}); err == nil {
		t.Fatal("native-only selection contributed HTTP rate history")
	}
	if err := third.BootstrapOAuthWorkloads(ctx); !errors.As(err, &conflict) {
		t.Fatal("newer authority epoch was not preserved", err)
	}
	if err := features3.Initialize(ctx); err != nil {
		t.Fatal("native-only current-authority startup", err)
	}
	if !nativeServer.Readiness(ctx).Ready {
		t.Fatal("native-only graph needed HTTP rate bootstrap")
	}
	if err := third.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// The HTTP owner uses a continuously refilling 120/minute token bucket,
	// not a fixed window. Count only successes and bound the combined admission
	// against elapsed authoritative server time; race instrumentation may allow
	// extra refill tokens. Both graphs must encounter the same depleted budget.
	const controlCapacity = 120
	var denied [2]bool
	for attempt := 0; !denied[0] || !denied[1]; attempt++ {
		if attempt == 2*controlCapacity {
			t.Fatal("two composed instances did not deplete one shared control budget")
		}
		graph := attempt % 2
		if graph == 0 {
			serving.Store(server)
		} else {
			serving.Store(reopened)
		}
		call("introspect", form, 200, 429)
		if lastStatus == 429 {
			denied[graph] = true
		}
	}
	var controlEnded time.Time
	var controlRows int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp(), count(*) FROM public.rate_limit_states WHERE state->>'policy_id'='oauth-protocol-client'`).Scan(&controlEnded, &controlRows); err != nil {
		t.Fatal(err)
	}
	if controlEnded.Before(controlStarted) || controlRows != 1 || controlSuccesses > controlCapacity+int(controlEnded.Sub(controlStarted)/(time.Minute/controlCapacity)) {
		t.Fatal("graphs exceeded the shared durable client allowance")
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(ctx); err != nil {
		t.Fatal(err)
	}
	before = counts()
	call("token", tokenForm, 503)
	if _, err := owner.Token(ctx, nativeRequest); err == nil {
		t.Fatal("retained native handle bypassed Close")
	}
	if server.Readiness(ctx).Ready || reopened.Readiness(ctx).Ready || counts() != before {
		t.Fatal("closed workload graph remained ready or wrote effects")
	}
	if err := f.pool.Raw().Ping(ctx); err != nil {
		t.Fatal("graph closed caller pool", err)
	}
}
