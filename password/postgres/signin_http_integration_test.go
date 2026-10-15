//go:build integration

package passwordpostgres

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// Actual routing, normalization, comparison, command, pre-auth, credential,
// session, CSRF and rate persistence are native. The surrounding fixture's
// explicit policy and risk callbacks are not provider or durable-risk proof.
func testNativeSigninHTTP(t *testing.T, ctx context.Context, service *SigninService, c SigninConfig, original password.SigninRequest, persistent bool) {
	t.Helper()
	for _, migration := range []ratepg.Migration{ratepg.SchemaMigration(), ratepg.AtomicSchemaMigration()} {
		if _, err := service.pool.Raw().Exec(ctx, migration.Up); err != nil {
			t.Fatal("signin rate migration", err)
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := service.pool.Raw().Exec(cleanup, migration.Down); err != nil {
				t.Error("signin rate cleanup", err)
			}
		}()
	}
	backend, err := ratepg.NewStrict(service.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "signin-native", IdentifierKey: [32]byte{91}, Now: time.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer rate.Close()
	flowCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	deviceKey, _ := session.NewBrowserDeviceKey(1, bytes.Repeat([]byte{92}, 32))
	deviceConfig := session.BrowserDeviceConfig{Namespace: "signin-native", Keys: []session.BrowserDeviceKey{deviceKey}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	codec, err := session.NewBrowserDeviceCodec(deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(ctx, time.Now(), original.TenantID, original.Origin)
	if err != nil {
		t.Fatal("original browser device", err)
	}
	deviceResponse := &http.Response{Header: http.Header{"Set-Cookie": []string{device.CookieHeader()}}}
	if len(deviceResponse.Cookies()) != 1 {
		t.Fatal("device cookie fixture")
	}
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "identity.test", TenantID: original.TenantID}}}
	config := passwordhttp.SigninConfig{Network: network, Service: service, Rate: rate, Origin: identityhttp.Origin(original.Origin), CallbackURL: original.CallbackURL, Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, FlowCookie: flowCookie, SessionCookie: c.Issuance.Cookie, Device: deviceConfig, ActorID: identity.ActorID(original.Caller.Request.Subject.ID), PolicyRevision: original.Caller.PolicyRevision, Audience: c.Profile.Audience, Now: time.Now, MaximumDuration: 5 * time.Second}
	feature, err := passwordhttp.NewSigninFeature(config)
	if err != nil {
		t.Fatal("native signin feature", err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	handler, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: network, HandlerTimeout: 5 * time.Second, Document: identityhttp.DocumentConfig{Title: "Native signin", Version: "1"}}, ops, nil)
	if err != nil || len(document.Operations()) != 1 || document.Version() != "3.1.1" {
		t.Fatal("selected signin router", err)
	}
	parsed, err := openapi.ParseJSON(ctx, bytes.NewReader(document.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(origin, secret string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{"flowID": string(original.PreAuthID), "identifier": string(original.Identifier), "password": secret, "callbackURL": original.CallbackURL, "remember": persistent})
		if err != nil {
			t.Fatal("signin input fixture")
		}
		defer clear(body)
		r := httptest.NewRequest(http.MethodPost, "/v1/password/signin", bytes.NewReader(body)).WithContext(ctx)
		r.Host, r.RemoteAddr, r.TLS = "identity.test", "192.0.2.1:1234", &tls.ConnectionState{}
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: original.Cookie.Token()})
		r.AddCookie(deviceResponse.Cookies()[0])
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if bytes.Contains(w.Body.Bytes(), []byte(secret)) || bytes.Contains(w.Body.Bytes(), []byte(original.Cookie.Token())) || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("signin response disclosed submitted custody")
		}
		return w
	}
	budgets := func(wantCount, wantTokens int) {
		t.Helper()
		var count, tokens int
		if err := service.pool.Raw().QueryRow(ctx, `SELECT count(*),COALESCE(sum((state->>'tokens')::integer),0) FROM rate_limit_states`).Scan(&count, &tokens); err != nil || count != wantCount || tokens != wantTokens {
			t.Fatal("signin rate phase changed", err, count, tokens)
		}
	}
	if w := invoke("https://foreign.test", "synthetic-wrong"); w.Code != 403 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("foreign origin entered signin", w.Code)
	}
	budgets(0, 0)
	var sessionsBefore int
	if err := service.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM signin_sessions.sessions WHERE tenant_id=$1 AND user_id=$2`, original.TenantID, signinTestUser).Scan(&sessionsBefore); err != nil {
		t.Fatal("primary session observation", err)
	}
	if w := invoke(original.Origin, "synthetic-wrong"); w.Code != 403 || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("wrong password issued authentication", w.Code)
	}
	budgets(2, 28)
	var sessionsAfter int
	if err := service.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM signin_sessions.sessions WHERE tenant_id=$1 AND user_id=$2`, original.TenantID, signinTestUser).Scan(&sessionsAfter); err != nil || sessionsAfter != sessionsBefore {
		t.Fatal("wrong password created an orphan session", err)
	}
	var flowState string
	if err := service.pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(original.PreAuthID)).Scan(&flowState); err != nil || flowState != "issued" {
		t.Fatal("wrong password consumed flow", err)
	}
	w := invoke(original.Origin, " synthetic-password ")
	var out passwordhttp.SigninResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 || !out.SignedIn || out.CommitOutcome != "committed" || out.Recovery == nil || out.SessionID == "" {
		t.Fatal("native signin HTTP failed", w.Code, out.CommitOutcome)
	}
	budgets(2, 26)
	if err := service.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM signin_sessions.sessions WHERE tenant_id=$1 AND user_id=$2`, original.TenantID, signinTestUser).Scan(&sessionsAfter); err != nil || sessionsAfter != sessionsBefore+1 {
		t.Fatal("HTTP signin did not create exactly one original session", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-session" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].SameSite != http.SameSiteLaxMode || (persistent && (cookies[0].MaxAge <= 0 || cookies[0].Expires.IsZero())) || (!persistent && (cookies[0].MaxAge != 0 || !cookies[0].Expires.IsZero())) {
		t.Fatal("native signin cookie policy diverged")
	}
	if w.Header().Get("X-CSRF-Token") == "" || bytes.Contains(w.Body.Bytes(), []byte(cookies[0].Value)) || bytes.Contains(w.Body.Bytes(), []byte(w.Header().Get("X-CSRF-Token"))) {
		t.Fatal("native credentials leaked into signin JSON")
	}
	repository, err := sessionpg.NewRepository(service.pool, c.Session)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := repository.Get(ctx, original.TenantID, out.SessionID)
	if err != nil || stored.Revoked || stored.FamilyRevoked {
		t.Fatal("delivered session missing from primary", err)
	}
	spec, err := stored.Session.Bindings()
	token, tokenErr := session.ParseToken(cookies[0].Value)
	digest, digestErr := token.Digest(c.Issuance.LookupKey, string(original.TenantID))
	csrf, csrfErr := session.ParseCSRFToken(w.Header().Get("X-CSRF-Token"))
	if err != nil || tokenErr != nil || digestErr != nil || csrfErr != nil || digest != spec.Lookup || spec.Remember != original.Remember || spec.UserID != signinTestUser || spec.Authentication.CredentialVersion != 7 || stored.Session.CSRFState().Check(session.CSRFBinding{TenantID: original.TenantID, SessionID: out.SessionID, SessionVersion: spec.Version}, csrf, c.CSRFKey) != nil {
		t.Fatal("delivered credentials diverged from original primary record")
	}
	if err := service.pool.Raw().QueryRow(ctx, `SELECT state FROM signin_sessions.preauth_transactions WHERE flow_id=$1`, string(original.PreAuthID)).Scan(&flowState); err != nil || flowState != "consumed" {
		t.Fatal("HTTP signin did not atomically consume original flow", err)
	}
	schema := parsed.Raw()
	for _, key := range []string{"paths", "/v1/password/signin", "post", "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
		var ok bool
		schema, ok = schema.Lookup(key)
		if !ok {
			t.Fatal("native signin response undocumented")
		}
	}
	instance, err := parse.JSON(ctx, bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(ctx, parsed, schema, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
	if err != nil || !report.Valid() {
		t.Fatal("native signin violates wire schema", err)
	}
	q := out.Recovery
	if q.CommandID != out.CommandID || q.TenantID != original.TenantID || q.FlowID != original.PreAuthID || q.ActorID != config.ActorID || q.ActorKind != original.Caller.Request.Subject.Kind {
		t.Fatal("HTTP recovery retargeted original signin")
	}
	recovery, err := password.NewSigninRecovery(identity.RecoveryQuery{CommandID: q.CommandID, TenantID: q.TenantID, AnonymousFlowID: string(q.FlowID), ActorID: q.ActorID, ActorKind: q.ActorKind, OperationID: "identity.password.signin"}, q.FlowID)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewSigninService(service.pool, c)
	if err != nil {
		t.Fatal(err)
	}
	history, err := restarted.RecoverSignin(ctx, password.SigninRecoveryRequest{Recovery: recovery, Cookie: original.Cookie, Caller: original.Caller, Origin: original.Origin, Network: "192.0.2.1", Device: device.DeviceID()})
	if err != nil || history.Validate() != nil || history.State != auth.SignInStateAuthenticated || history.SessionID != out.SessionID || !history.Issuance.Replayed || history.Issuance.CommitOutcome != identity.CommitOutcomeCommitted || history.Issuance.Token != (session.Token{}) || history.CSRFToken != (session.CSRFToken{}) || history.Issuance.Cookie.Name != "" {
		t.Fatal("restarted HTTP signin recovery lost credential-free history", err)
	}
}
