//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-identifier/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

func TestReferencePostgresAPIKeyHTTPS(t *testing.T) {
	for _, upgrade := range []bool{false, true} {
		name := "fresh"
		if upgrade {
			name = "populated-upgrade"
		}
		t.Run(name, func(t *testing.T) {
			proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{apiKey: true, apiKeyUpgrade: upgrade, postgresBaseline: true})
		})
	}
}

type referenceAPIKeyPolicy struct{}

func (referenceAPIKeyPolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if string(r.Tenant) == otpTenant && c.PolicyRevision == 9 {
		allow := false
		if r.Subject.Kind == authorization.SubjectUser {
			switch r.Action {
			case "identity.apikey.create", "identity.apikey.rotate", "identity.apikey.delete", "identity.apikey.update":
				allow = r.Resource.Type == "api-key" && r.Resource.ID == "reference-automation" || r.Resource.Type == "identity.user" && string(r.Resource.ID) == string(r.Subject.ID) || r.Resource.Type == "identity.request-admission" && string(r.Resource.ID) == string(r.Action)
			case "invoice.read":
				allow = r.Resource.Type == "api-key" && r.Resource.ID == "reference-automation"
			}
		}
		if r.Action == "identity.apikey.verify" {
			allow = r.Subject.Kind == authorization.SubjectAPIKey && r.Resource.Type == "identity.user" || r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == "reference-automation" && r.Resource.Type == "identity.anonymous-flow"
		}
		if allow {
			return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func configureReferenceAPIKey(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	configuration, err := apikey.NewConfiguration(apikey.ConfigurationSpec{ID: "reference-automation", Revision: 1, State: apikey.ConfigurationActive, Issuer: origin, Environment: "reference", Audience: "resource-api", PermissionReduction: apikey.PermissionReductionNarrow, MaximumLifetime: 90 * 24 * time.Hour, MaximumRead: time.Second, ClockUncertainty: time.Millisecond, DecisionRaceBudget: time.Millisecond, Quota: apikey.QuotaUnlimited, Cache: apikey.CacheDisabled})
	if err != nil {
		t.Fatal(err)
	}
	pepper, err := apikey.NewPepper(1, bytes.Repeat([]byte{161}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters := c.PasswordSignup.Counters
	counters.EnforceLockouts = true
	c.APIKey = &reference.APIKeyConfiguration{Configuration: configuration, MaximumDuration: 2 * time.Second, PolicyID: "reference-api-key", Pepper: pepper, Counters: counters, RiskConfigurationID: "reference-api-key-providers-v1", RiskKeys: c.OTP.RiskKeys, ActiveEnvelopeKeyID: "api-key-envelope", RetainedEnvelopeKeys: map[string][]byte{"api-key-envelope": bytes.Repeat([]byte{162}, 32)}}
	c.HTTPAPIKey = &reference.HTTPAPIKeyConfiguration{Create: true, Rotate: true, Revoke: true, SecretNamespace: "reference-secret", SecretKey: [32]byte{163}}
}

// Install only this selected transport's own rate history before the baseline
// HTTP graph can install prerequisites for any other feature. The independent
// native consumer proves actual SQL admission, not just a catalog entry.
func proveReferenceAPIKeyOnlyRateMigrations(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, workerConfigs []deliverypg.WorkerConfig) {
	t.Helper()
	c.HTTPPreAuth, c.HTTPSession, c.HTTPPasswordSignup, c.HTTPPasswordSignin, c.HTTPRegistrationVerification, c.HTTPEmailSignin = nil, nil, nil, nil, nil, nil
	stores, _ := composeReferenceAPIKeyGraph(t, c, deps, workerConfigs)
	request := applyRequest(t, ctx, stores, []reference.ModuleID{"rate-limit/postgres"})
	request.CommandID = "migration_apikey_rate_only_0001"
	var err error
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("apply-api-key-only-rate-original"))
	if err != nil {
		t.Fatal(err)
	}
	out, err := stores.ReferenceMigrationApply(ctx, request)
	if err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("API-key-only native rate migration", err)
	}
	backend, err := ratepg.OpenStrict(ctx, f.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: 500 * time.Millisecond, Clock: ratepg.ServerClock}, RollbackTimeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: backend, Namespace: c.HTTPAPIKey.SecretNamespace, Key: c.HTTPAPIKey.SecretKey, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { limiter.Close() })
	resolver, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 8192, MaximumURLBytes: 2048, MaximumBodyBytes: 65536, MaximumDecodedBytes: 16384, MaximumFields: 128, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "127.0.0.1", TenantID: otpTenant}}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://127.0.0.1/v1/apikey/create", nil)
	r.RequestURI = "/v1/apikey/create"
	r.RemoteAddr = "127.0.0.1:1234"
	facts, err := resolver.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("api-key-only-rate-consumer"))
	if err != nil {
		t.Fatal(err)
	}
	// This scopes a rate budget, not an identity/session authority. The actual
	// authenticated route is exercised below after genuine registration.
	admitted, err := limiter.Admit(ctx, facts, identityhttp.KeyedSecretRateRequest{OperationID: "identity.apikey.create", UserID: "AAAAAAAAAAAAAAAAAAAAAg", IdempotencyKey: key})
	if err != nil || !admitted.Allowed {
		t.Fatal("API-key-only migration cannot serve its actual keyed rate owner", err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

// Reuse the actual registration/verification/browser baseline, then explicitly
// select native bearer signin. No token is reclassified and no CSRF is stripped.
func proveReferenceAPIKey(t *testing.T, ctx context.Context, f liveStores, c reference.StoreConfiguration, deps reference.ReferenceDependencies, workerConfigs []deliverypg.WorkerConfig, config reference.ReferenceConfig, server *reference.Server, client *http.Client, origin string, user identity.UserID, cookies []*http.Cookie, upgrade bool) {
	t.Helper()
	if upgrade {
		for _, op := range server.OpenAPI().Operations() {
			if strings.HasPrefix(op.Record.OperationID, "identity.apikey.") {
				t.Fatal("unselected API-key operation advertised")
			}
		}
		request, _ := http.NewRequestWithContext(ctx, "POST", origin+"/v1/apikey/create", strings.NewReader("{}"))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(response.Body, 16385))
		closeErr := response.Body.Close()
		if response.StatusCode != 404 || readErr != nil || closeErr != nil {
			t.Fatal("disabled API-key route exposed")
		}
		configureReferenceAPIKey(t, &c, origin)
	}
	// Keep all baseline cookie owners intact. Only this password issuer switches
	// to its supported native bearer profile, and its browser route is unselected.
	signin := *c.PasswordSignin
	signin.Native.Transport, signin.Native.CSRFKey, signin.Native.Issuance.Cookie = password.BearerSignin, session.CSRFKey{}, session.CookiePolicy{}
	c.PasswordSignin = &signin
	if invalid, err := reference.ComposeStores(c, deps); err == nil {
		_ = invalid.Close(ctx)
		t.Fatal("native bearer issuer accepted the incompatible browser signin route")
	}
	c.HTTPPasswordSignin = nil
	stores, features := composeReferenceAPIKeyGraph(t, c, deps, workerConfigs)
	owner, err := features.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Create(ctx, apikey.CreateRequest{Authentication: apikey.Authentication{TenantID: otpTenant}}); err == nil {
		t.Fatal("uninitialized graph admitted a key operation")
	}
	metadata := func() [3]int64 {
		t.Helper()
		var n [3]int64
		if err := f.pool.Raw().QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.users),(SELECT count(*) FROM identity.identifiers WHERE verified),(SELECT count(*) FROM session_store.sessions)`).Scan(&n[0], &n[1], &n[2]); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := metadata()
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity", "rate-limit/postgres", "identity/password/postgres", "identity/mfa/postgres", "capability/postgres/identity", "identity/apikey/postgres"}
	request := applyRequest(t, ctx, stores, modules)
	request.CommandID = "migration_apikey_selected_0001"
	request.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("apply-api-key-selected-original"))
	if err != nil {
		t.Fatal(err)
	}
	if upgrade && len(request.Plan.Steps) == 0 {
		t.Fatal("baseline preinstalled disabled API-key migrations")
	}
	for range 2 {
		out, err := stores.ReferenceMigrationApply(ctx, request)
		if err != nil || out.Result.State() != reference.MigrationApplied || metadata() != before {
			t.Fatal("API-key migration/retry changed populated baseline", err)
		}
	}
	for range 2 {
		if err := features.Initialize(ctx); err != nil {
			t.Fatal("API-key initialize/reconstruction", err)
		}
	}
	current, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 1 {
		t.Fatal("genuine baseline session absent")
	}
	token, err := session.ParseToken(cookies[0].Value)
	if err != nil {
		t.Fatal("baseline token")
	}
	credential, _ := session.NewCredential(session.CredentialCookie, token)
	retained, err := current.Get(ctx, session.GetRequest{TenantID: otpTenant, Credential: credential})
	if err != nil || !retained.Authenticated {
		t.Fatal("API-key upgrade lost baseline session", err)
	}
	caller := referenceAPIKeyBearer(t, ctx, features, c, origin, user)
	selectedServer, err := reference.NewServer(config, deps, features)
	if err != nil {
		t.Fatal("API-key actual selected HTTP composition", err)
	}
	for _, op := range selectedServer.OpenAPI().Operations() {
		if op.Record.OperationID == "identity.password.signin" {
			t.Fatal("native bearer selection advertised browser signin")
		}
	}
	api := httptest.NewTLSServer(selectedServer.Handler())
	t.Cleanup(api.Close)
	apiClient := api.Client()
	apiClient.Timeout = 5 * time.Second
	type reply struct {
		Committed bool               `json:"committed"`
		CommandID identity.CommandID `json:"commandID"`
		Secret    string             `json:"secret"`
		Error     string             `json:"error"`
		Key       struct {
			ID          apikey.KeyID `json:"id"`
			Version     uint64       `json:"version"`
			Permissions []string     `json:"permissions"`
			ExpiresAt   time.Time    `json:"expiresAt"`
		} `json:"key"`
	}
	call := func(action, key string, body any, bearer string, cookie bool) (int, reply) {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r, err := http.NewRequestWithContext(ctx, "POST", api.URL+"/v1/apikey/"+action, bytes.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", key)
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		if cookie {
			r.AddCookie(cookies[0])
		}
		response, err := apiClient.Do(r)
		if err != nil {
			t.Fatal("API-key Reference HTTPS", err)
		}
		payload, readErr := io.ReadAll(io.LimitReader(response.Body, 131073))
		closeErr := response.Body.Close()
		var out reply
		if readErr != nil || closeErr != nil || len(payload) > 131072 || json.Unmarshal(payload, &out) != nil || response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 || bytes.Contains(payload, []byte(caller.Bearer.Token())) {
			t.Fatal("API-key response custody")
		}
		return response.StatusCode, out
	}
	expires := time.Now().UTC().Add(48 * time.Hour).Truncate(time.Microsecond)
	input := map[string]any{"name": "Reference integration", "permissions": []string{"invoice.read"}, "expiresAt": expires}
	if status, out := call("create", "reference-cookie-denied", input, "", true); status == 200 || out.Committed || out.Secret != "" {
		t.Fatal("cookie supplied bearer authority")
	}
	status, created := call("create", "reference-original-create", input, caller.Bearer.Token(), false)
	if status != 200 || !created.Committed || created.Secret == "" || created.Key.ID == "" || !created.Key.ExpiresAt.Equal(expires) {
		t.Fatal("Reference API-key issuance", status, created.Error)
	}
	verify := func(wire string, allowed bool) {
		t.Helper()
		secret, err := apikey.ParseSecret(wire)
		if err != nil {
			t.Fatal("Reference key malformed")
		}
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		out, err := owner.VerifyAndConsume(ctx, apikey.AtomicVerificationRequest{AttemptID: apikey.VerificationAttemptID(id), TenantID: otpTenant, ConfigurationID: c.APIKey.Configuration.Spec().ID, ConfigurationRevision: 1, Secret: secret, RequiredPermissions: []string{"invoice.read"}})
		if allowed {
			if err != nil || out.Result == nil || out.Result.ValidateAt(c.APIKey.Configuration, time.Now()) != nil {
				t.Fatal("Reference key could not authenticate", err)
			}
		} else if !errors.Is(err, apikey.ErrDenied) || out.Result != nil {
			t.Fatal("terminal Reference key authenticated", err)
		}
	}
	verify(created.Secret, true)
	// Restart only the owned graph, retaining the native primary, immutable
	// custody and original command. The retry must not mint or reveal again.
	nextStores, nextFeatures := composeReferenceAPIKeyGraph(t, c, deps, workerConfigs)
	if err := nextFeatures.Initialize(ctx); err != nil {
		t.Fatal("API-key original-command reconstruction", err)
	}
	nextServer, err := reference.NewServer(config, deps, nextFeatures)
	if err != nil {
		t.Fatal(err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	stores, features = nextStores, nextFeatures
	owner, err = features.APIKeys()
	if err != nil {
		t.Fatal(err)
	}
	api = httptest.NewTLSServer(nextServer.Handler())
	t.Cleanup(api.Close)
	apiClient = api.Client()
	apiClient.Timeout = 5 * time.Second
	status, replay := call("create", "reference-original-create", input, caller.Bearer.Token(), false)
	if status != 200 || !replay.Committed || replay.CommandID != created.CommandID || replay.Secret != "" {
		t.Fatal("Reference original retry revealed/reissued")
	}
	status, rotated := call("rotate", "reference-original-rotate", map[string]any{"keyID": created.Key.ID, "expectedVersion": created.Key.Version}, caller.Bearer.Token(), false)
	if status != 200 || !rotated.Committed || rotated.Secret == "" || rotated.Key.ID == created.Key.ID || !rotated.Key.ExpiresAt.Equal(expires) || !slices.Equal(created.Key.Permissions, rotated.Key.Permissions) {
		t.Fatal("Reference rotation widened/lost authority", status, rotated.Error)
	}
	verify(created.Secret, false)
	verify(rotated.Secret, true)
	status, revoked := call("delete", "reference-original-revoke", map[string]any{"keyID": rotated.Key.ID, "expectedVersion": rotated.Key.Version}, caller.Bearer.Token(), false)
	if status != 200 || !revoked.Committed || revoked.Secret != "" {
		t.Fatal("Reference revocation", status, revoked.Error)
	}
	verify(rotated.Secret, false)
	if metadata()[0] != before[0] || metadata()[1] != before[1] {
		t.Fatal("API-key lifecycle changed registered identity")
	}
	sessions, err := features.Sessions()
	if err != nil {
		t.Fatal(err)
	}
	bearerToken, err := session.ParseToken(caller.Bearer.Token())
	if err != nil {
		t.Fatal("issued bearer invalid")
	}
	bearerCredential, err := session.NewCredential(session.CredentialBearer, bearerToken)
	if err != nil {
		t.Fatal(err)
	}
	signoutID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	signedOut, err := sessions.SignOut(ctx, session.SignOutRequest{TenantID: otpTenant, CommandID: signoutID, CorrelationID: string(signoutID), Transport: session.CredentialBearer, Credential: bearerCredential}, session.CSRFToken{})
	if err != nil || !signedOut.SignedOut || signedOut.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("Reference bearer signout", err)
	}
	if status, out := call("create", "reference-original-create", input, caller.Bearer.Token(), false); status == 200 || out.Committed || out.Secret != "" {
		t.Fatal("revoked session recovered management authority")
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.VerifyAndConsume(ctx, apikey.AtomicVerificationRequest{TenantID: otpTenant}); err == nil {
		t.Fatal("retained Reference verifier survived graph close")
	}
	if status, out := call("create", "reference-after-close", input, caller.Bearer.Token(), false); status == 200 || out.Secret != "" {
		t.Fatal("retained HTTP handler survived graph close")
	}
}

func composeReferenceAPIKeyGraph(t *testing.T, c reference.StoreConfiguration, deps reference.ReferenceDependencies, workerConfigs []deliverypg.WorkerConfig) (reference.StoreSet, reference.FeatureSet) {
	t.Helper()
	stores, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal("API-key actual bearer graph composition", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := stores.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, workerConfigs...)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	return stores, features
}

func referenceAPIKeyBearer(t *testing.T, ctx context.Context, features reference.FeatureSet, c reference.StoreConfiguration, origin string, user identity.UserID) apikey.Authentication {
	t.Helper()
	issuer, err := features.PasswordPreAuth()
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.RememberDefault, c.HTTPPreAuth.Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := issuer.Prepare(ctx, session.PreAuthPrepareInput{CommandID: id, TenantID: otpTenant, CorrelationID: string(id), Remember: remember})
	if err != nil {
		t.Fatal(err)
	}
	issued, err := issuer.Issue(ctx, prepared)
	if err != nil || issued.CommitOutcome != identity.CommitOutcomeCommitted {
		t.Fatal("Reference original bearer flow", err)
	}
	bindings, err := issued.Flow.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	flowToken, err := issued.Token.Reveal()
	if err != nil {
		t.Fatal("original flow custody")
	}
	secret, err := primitive.NewSecret([]byte("synthetic-registration-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	input, err := identifier.NewInput("registered@example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := features.PasswordSignin()
	if err != nil {
		t.Fatal(err)
	}
	caller := authorization.DecisionContext{PolicyRevision: 9, Request: authorization.Request{Subject: authorization.Subject{Kind: authorization.SubjectServiceAccount, ID: "AAAAAAAAAAAAAAAAAAAAAw"}, Tenant: otpTenant, Action: "identity.password.signin", Resource: authorization.Resource{Type: "identity.request-admission", ID: "identity.password.signin"}}}
	result, err := owner.Signin(ctx, password.SigninRequest{TenantID: otpTenant, PreAuthID: bindings.Binding.ID, Cookie: auth.NewBearerCredential(flowToken), Identifier: input, Password: secret, Remember: remember, Caller: caller, Origin: origin, CallbackURL: c.PasswordSignin.Native.CallbackURLs[0], Network: "127.0.0.1", Device: "reference-api-key"})
	if err != nil || result.Transport != password.BearerSignin || result.State != auth.SignInStateAuthenticated || result.Issuance.Session.CSRFState() != (session.CSRFState{}) {
		t.Fatal("Reference genuine bearer signin", err)
	}
	bound, err := result.Issuance.Session.Bindings()
	if err != nil || bound.UserID != user {
		t.Fatal("bearer signin changed registered identity")
	}
	wire, err := result.Issuance.Token.Reveal()
	if err != nil {
		t.Fatal("original bearer custody")
	}
	return apikey.Authentication{TenantID: otpTenant, Bearer: auth.NewBearerCredential(wire)}
}
