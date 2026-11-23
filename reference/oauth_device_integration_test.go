//go:build integration

package reference_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-clock"
	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/reference"
	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/faustbrian/go-oauth-server/device"
	oauthpg "github.com/faustbrian/go-oauth-server/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

const referenceDeviceClient = "reference-device"

// Only this registered client and the authenticated user's own mutation are
// admitted. The native service still owns current client and human authority.
type referenceDevicePolicy struct{}

func (referenceDevicePolicy) Decide(ctx context.Context, c authorization.DecisionContext) (authorization.Decision, error) {
	if err := ctx.Err(); err != nil {
		return authorization.Decision{}, err
	}
	r := c.Request
	if r.Tenant == otpTenant && c.PolicyRevision == 9 {
		switch r.Action {
		case "identity.oauth-server.device-authorize", "identity.oauth-server.device-authorize.recover", "identity.oauth-server.device-token", "identity.oauth-server.device-token.recover":
			_, err := identity.ParseCommandID(string(r.Resource.ID))
			if r.Subject.Kind == authorization.SubjectServiceAccount && r.Subject.ID == referenceDeviceClient && r.Resource.Type == "identity.anonymous-flow" && err == nil {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		case "identity.oauth-server.device-approve", "identity.oauth-server.device-approve.recover", "identity.oauth-server.device-deny", "identity.oauth-server.device-deny.recover":
			if r.Subject.Kind == authorization.SubjectUser && r.Subject.ID != "" && r.Resource.Type == "identity.user" && r.Resource.ID == authorization.ResourceID(r.Subject.ID) {
				return authorization.Decision{Outcome: authorization.Allow, Revision: 9}, nil
			}
		}
	}
	return (referenceRegistrationPolicy{}).Decide(ctx, c)
}

func configureReferenceDevice(t *testing.T, c *reference.StoreConfiguration, origin string) {
	t.Helper()
	issuer, err := oauth.NewIssuer(origin)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := oauth.NewPlatformOwner("deployment")
	if err != nil {
		t.Fatal(err)
	}
	scopes, err := oauth.NewScopeCatalog([]string{"identity:read"})
	if err != nil {
		t.Fatal(err)
	}
	var tokenMaterial, lookupMaterial, intent, requestMaterial [32]byte
	for _, key := range []*[32]byte{&tokenMaterial, &lookupMaterial, &intent, &requestMaterial} {
		if _, err := rand.Read(key[:]); err != nil {
			t.Fatal("device fixture entropy unavailable")
		}
	}
	tokenKey, err := oauth.NewTokenDigestKey(1, tokenMaterial[:])
	clear(tokenMaterial[:])
	if err != nil {
		t.Fatal(err)
	}
	lookupKey, err := oauth.NewTokenDigestKey(1, lookupMaterial[:])
	clear(lookupMaterial[:])
	if err != nil {
		t.Fatal(err)
	}
	query := c.OTP.RequestKeys.Policy
	requestKeys, err := kernel.NewRequestKeyConfig("reference-device", requestMaterial, query)
	clear(requestMaterial[:])
	if err != nil {
		t.Fatal(err)
	}
	protectedOAuthPolicy := registrationRiskPolicy(t, 9, false)
	counters := c.PasswordSignup.Counters
	counters.CommandCounters = &risk.CommandCounterPolicyConfig{Policy: protectedOAuthPolicy}
	counters.EnforceLockouts = true
	for _, operation := range []risk.Action{"identity.oauth-server.authorize", "identity.oauth-server.continue", "identity.oauth-server.token", "identity.oauth-server.revoke", "identity.oauth-server.consent-delete", "identity.oauth-server.consent-update", "identity.oauth-server.device-authorize", "identity.oauth-server.device-approve", "identity.oauth-server.device-deny", "identity.oauth-server.device-token"} {
		admitted, err := protectedOAuthPolicy.Admit(operation)
		if err != nil || admitted.Profile.Class != risk.Privileged || !slices.Equal(admitted.Profile.RequiredSignals, []string{"velocity"}) {
			t.Fatal("device graph lacks native protected velocity policy")
		}
	}
	protocol := oauth.Config{Issuer: issuer, Environment: "reference-device", Resource: "https://resource.example", Scopes: scopes,
		Clients:   []oauth.Client{{ID: referenceDeviceClient, Owner: owner, Version: 1, Public: true, AuthenticationMethod: "none", DeviceAuthorization: true, Redirects: []string{"https://client.example/callback"}, Scopes: scopes.Scopes(), Resource: "https://resource.example"}},
		Discovery: oauth.DiscoveryConfig{Enabled: true, AuthorizationEndpoint: origin + "/oauth2/authorize", TokenEndpoint: origin + "/oauth2/token", RevocationEndpoint: origin + "/oauth2/revoke"},
		Clock:     clock.System{}, MaximumDuration: c.OTP.Timeout, CodeTTL: time.Minute, ContinuationTTL: time.Minute, AccessTTL: time.Minute, RefreshTTL: time.Hour}
	policy := device.Config{Enabled: true, TenantID: otpTenant, VerificationURI: origin + "/device", TokenEndpoint: origin + "/oauth2/token", AuthorizationEndpoint: origin + "/oauth2/device_authorization", TTL: time.Minute, PollInterval: 5 * time.Second, VerificationURICompleteBytes: 512, LookupLimit: 32}
	c.OAuthDevice = &reference.OAuthDeviceConfiguration{Protocol: protocol, Schema: "oauth_store", TokenKeys: []oauth.TokenDigestKey{tokenKey}, ActiveTokenKeyVersion: 1, IntentKey: intent, ActiveEnvelopeKeyID: "issue-envelope", Coordinator: c.PasswordSignup.Native.Coordinator, RequestKeys: requestKeys, PolicyID: "reference-device", Counters: counters, Device: oauthpg.DeviceConfig{Policy: policy, LookupKeys: []oauth.TokenDigestKey{lookupKey}, ActiveLookupKeyVersion: 1}}
	c.HTTPOAuthDevice = &reference.HTTPOAuthDeviceConfiguration{Namespace: "reference-device-http"}
}

func TestReferencePostgresOAuthDeviceHTTPS(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, oauthDevice: true})
}

func TestReferencePostgresOAuthDeviceResumesInstalledBase(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, oauthDevice: true, oauthDeviceBaseInstalled: true})
}

func installReferenceDeviceBase(t *testing.T, ctx context.Context, pool *database.Pool) {
	t.Helper()
	db := stdlib.OpenDBFromPool(pool.Raw())
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := backend.ForNamespace("identity_oauth_device")
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(oauthpg.MigrationSource{Schema: "oauth_store", Version: 1}, owned)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("install original native OAuth migration", err)
	}
}

func assertReferenceDeviceSuffixPlan(t *testing.T, plan reference.MigrationPlan) {
	t.Helper()
	var versions []uint64
	for _, step := range plan.Steps {
		if step.Owner == "oauth-server/postgres" {
			versions = append(versions, step.ToVersion)
		}
	}
	if !slices.Equal(versions, []uint64{2, 3}) {
		t.Fatal("expected only the unapplied consent and device steps", versions)
	}
}

func proveReferenceDeviceReadiness(t *testing.T, ctx context.Context, server *reference.Server, pool *database.Pool) {
	t.Helper()
	for _, object := range []struct{ name, hide, restore string }{
		{"device effects table", `ALTER TABLE oauth_store.device_effects RENAME TO fixture_missing_device_effects`, `ALTER TABLE oauth_store.fixture_missing_device_effects RENAME TO device_effects`},
		{"device root column", `ALTER TABLE oauth_store.artifacts RENAME COLUMN device_root_grant TO fixture_missing_device_root`, `ALTER TABLE oauth_store.artifacts RENAME COLUMN fixture_missing_device_root TO device_root_grant`},
		{"device lineage constraint", `ALTER TABLE oauth_store.artifacts RENAME CONSTRAINT artifacts_device_origin TO fixture_missing_device_origin`, `ALTER TABLE oauth_store.artifacts RENAME CONSTRAINT fixture_missing_device_origin TO artifacts_device_origin`},
	} {
		t.Run(object.name, func(t *testing.T) {
			if _, err := pool.Raw().Exec(ctx, object.hide); err != nil {
				t.Fatal("could not hide the selected native schema object", err)
			}
			missing := server.Readiness(ctx)
			if _, err := pool.Raw().Exec(ctx, object.restore); err != nil {
				t.Fatal("could not restore the selected native schema object", err)
			}
			if missing.Ready || !slices.Contains(missing.Failures, reference.ReadinessCode("schema_incompatible")) || !server.Readiness(ctx).Ready {
				t.Fatal("readiness ignored an unavailable device schema object", missing.Failures)
			}
		})
	}
}

func proveReferenceDeviceWithoutHTTP(t *testing.T, ctx context.Context, c reference.StoreConfiguration, d reference.ReferenceDependencies, config reference.ReferenceConfig, delivery []deliverypg.WorkerConfig) {
	t.Helper()
	c.HTTPOAuthDevice = nil
	stores, err := reference.ComposeStores(c, d)
	if err != nil {
		t.Fatal("native device selection required HTTP", err)
	}
	defer func() {
		if err := stores.Close(ctx); err != nil {
			t.Error("close native-only Reference graph", err)
		}
	}()
	providers, err := reference.ComposeProviders(stores)
	if err != nil {
		t.Fatal(err)
	}
	workers, err := reference.ComposeWorkers(stores, providers, delivery...)
	if err != nil {
		t.Fatal(err)
	}
	features, err := reference.ComposeFeatures(stores, providers, workers)
	if err != nil {
		t.Fatal(err)
	}
	server, err := reference.NewServer(config, d, features)
	if err != nil {
		t.Fatal(err)
	}
	for _, op := range server.OpenAPI().Operations() {
		if strings.HasPrefix(op.Record.OperationID, "identity.oauth-server.") {
			t.Fatal("native-only selection advertised an issuer operation", op.Record.OperationID)
		}
	}
}

func proveReferenceDeviceHTTP(t *testing.T, ctx context.Context, client *http.Client, base, origin string, cookies []*http.Cookie, csrf string) {
	t.Helper()
	if len(cookies) != 1 || len(csrf) != 43 {
		t.Fatal("genuine signin omitted browser cookie or CSRF custody")
	}
	call := func(method, path, contentType, body, selectedOrigin, selectedCSRF string, selectedCookies []*http.Cookie, status int) map[string]json.RawMessage {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, base+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		if selectedOrigin != "" {
			r.Header.Set("Origin", selectedOrigin)
		}
		if selectedCSRF != "" {
			r.Header.Set("X-CSRF-Token", selectedCSRF)
		}
		for _, cookie := range selectedCookies {
			r.AddCookie(cookie)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("actual device HTTPS request failed")
		}
		defer response.Body.Close()
		wire, err := io.ReadAll(io.LimitReader(response.Body, 16385))
		if err != nil || len(wire) > 16384 || response.StatusCode != status {
			t.Fatal("device HTTPS status or bounded body", method, strings.Split(path, "?")[0], response.StatusCode, "expected", status)
		}
		if response.Header.Get("Cache-Control") != "no-store" || len(response.Cookies()) != 0 {
			t.Fatal("device operation changed browser custody or cache policy")
		}
		if selectedOrigin != "" && selectedOrigin != origin && status == http.StatusForbidden {
			// Reference's outer CORS guard denies an unselected origin before
			// the device handler can render a protocol error.
			if string(wire) != "identity.http.origin_denied\n" {
				t.Fatal("unexpected Reference cross-origin denial envelope")
			}
			return nil
		}
		var out map[string]json.RawMessage
		if json.Unmarshal(wire, &out) != nil {
			t.Fatal("invalid device JSON response", method, strings.Split(path, "?")[0], status)
		}
		if status != http.StatusOK && (len(out) != 1 || out["error"] == nil) {
			t.Fatal("device denial disclosed credentials or private metadata")
		}
		return out
	}
	text := func(out map[string]json.RawMessage, key string) string {
		t.Helper()
		var value string
		if json.Unmarshal(out[key], &value) != nil || value == "" {
			t.Fatal("device response missing bounded text field", key)
		}
		return value
	}
	requireError := func(out map[string]json.RawMessage, want string) {
		t.Helper()
		if got := text(out, "error"); got != want {
			t.Fatal("unexpected device protocol error", got, "expected", want)
		}
	}
	type issuedDevice struct {
		code, user string
		interval   time.Duration
	}
	issue := func() issuedDevice {
		t.Helper()
		form := url.Values{"client_id": {referenceDeviceClient}, "scope": {"identity:read"}, "resource": {"https://resource.example"}}
		out := call(http.MethodPost, "/oauth2/device_authorization", "application/x-www-form-urlencoded", form.Encode(), "", "", nil, 200)
		var interval, lifetime int
		code, user := text(out, "device_code"), text(out, "user_code")
		decoded, err := base64.RawURLEncoding.DecodeString(code)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != code || len(out) != 6 || len(user) != 9 || user[4] != '-' {
			t.Fatal("device issuance lost canonical code or closed response shape")
		}
		if text(out, "verification_uri") != origin+"/device" || text(out, "verification_uri_complete") != origin+"/device?"+(url.Values{"user_code": {user}}).Encode() || json.Unmarshal(out["interval"], &interval) != nil || interval != 5 || json.Unmarshal(out["expires_in"], &lifetime) != nil || lifetime < 1 || lifetime > 60 {
			t.Fatal("device issuance changed selected URI, lifetime or poll interval")
		}
		return issuedDevice{code: code, user: user, interval: time.Duration(interval) * time.Second}
	}
	poll := func(issued issuedDevice, status int) map[string]json.RawMessage {
		t.Helper()
		form := url.Values{"client_id": {referenceDeviceClient}, "grant_type": {device.GrantType}, "device_code": {issued.code}}
		return call(http.MethodPost, "/oauth2/token", "application/x-www-form-urlencoded", form.Encode(), "", "", nil, status)
	}
	mutate := func(action string, body map[string]string, selectedOrigin, selectedCSRF string, status int) map[string]json.RawMessage {
		t.Helper()
		wire, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return call(http.MethodPost, "/v1/oauth-server/device-"+action, "application/json", string(wire), selectedOrigin, selectedCSRF, cookies, status)
	}
	approved, pending, denied := issue(), issue(), issue()
	// Both live polling cases become eligible in one real-clock wait, while
	// approval/denial and their rejected attempts run inside that interval.
	pollAt := time.Now().Add(pending.interval)
	inspectPath := "/v1/oauth-server/device-inspect?" + (url.Values{"user_code": {strings.ToLower(approved.user)}}).Encode()
	requireError(call(http.MethodGet, inspectPath, "", "", "", "", nil, 400), "invalid_request")
	prompt := call(http.MethodGet, inspectPath, "", "", "", "", cookies, 200)
	var scopes, resources []string
	var expiry time.Time
	if len(prompt) != 5 || text(prompt, "canonical_user_code") != approved.user || text(prompt, "client_display_name") != referenceDeviceClient || json.Unmarshal(prompt["scopes"], &scopes) != nil || !slices.Equal(scopes, []string{"identity:read"}) || json.Unmarshal(prompt["resources"], &resources) != nil || !slices.Equal(resources, []string{"https://resource.example"}) || json.Unmarshal(prompt["expires_at"], &expiry) != nil || !expiry.After(pollAt) {
		t.Fatal("authenticated device inspection lost bounded canonical display")
	}
	approval := map[string]string{"user_code": approved.user, "confirmed_user_code": approved.user}
	requireError(mutate("approve", map[string]string{"user_code": approved.user}, origin, csrf, 400), "invalid_request")
	requireError(mutate("approve", map[string]string{"user_code": approved.user, "confirmed_user_code": denied.user}, origin, csrf, 400), "access_denied")
	requireError(mutate("approve", approval, origin, "", 403), "origin_or_csrf_denied")
	wrongCSRF := "A" + csrf[1:]
	if wrongCSRF == csrf {
		wrongCSRF = "B" + csrf[1:]
	}
	requireError(mutate("approve", approval, origin, wrongCSRF, 400), "access_denied")
	mutate("approve", approval, "https://other.example", csrf, 403)
	if out := mutate("approve", approval, origin, csrf, 200); len(out) != 2 || text(out, "state") != "approved" {
		t.Fatal("explicit authenticated code match did not approve")
	}
	denial := map[string]string{"user_code": denied.user}
	for range 2 {
		if out := mutate("deny", denial, origin, csrf, 200); len(out) != 2 || text(out, "state") != "denied" {
			t.Fatal("genuine device denial was not idempotent")
		}
	}
	requireError(poll(denied, 400), "access_denied")
	timer := time.NewTimer(time.Until(pollAt))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		t.Fatal("device journey expired before advertised poll interval")
	case <-timer.C:
	}
	requireError(poll(pending, 400), "authorization_pending")
	tokens := poll(approved, 200)
	var lifetime int
	if len(tokens) != 5 || text(tokens, "token_type") != "Bearer" || text(tokens, "scope") != "identity:read" || json.Unmarshal(tokens["expires_in"], &lifetime) != nil || lifetime < 1 || lifetime > 60 {
		t.Fatal("approved device did not issue bounded native tokens")
	}
	for _, name := range []string{"access_token", "refresh_token"} {
		secret := text(tokens, name)
		decoded, err := base64.RawURLEncoding.DecodeString(secret)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != secret || secret == approved.code || secret == csrf {
			t.Fatal("device token custody or canonical format changed", name)
		}
	}
	requireError(poll(approved, 400), "access_denied")
}
