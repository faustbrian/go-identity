package ssohttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

type signinStartProbe struct {
	seen    sso.SigninStartRequest
	tenant  identity.TenantID
	browser SigninBrowser
	calls   int
	result  sso.SigninStartResult
}

func (p *signinStartProbe) StartSSOOIDC(_ context.Context, tenant identity.TenantID, request sso.SigninStartRequest, browser SigninBrowser) (sso.SigninStartResult, error) {
	p.calls++
	p.tenant, p.seen, p.browser = tenant, request, browser
	if p.result.Completion.Outcome == identity.CommitOutcomeCommitted {
		return p.result, nil
	}
	return sso.SigninStartResult{}, sso.ErrForbidden
}

func TestEnterpriseSigninStartUsesTrustedBrowserAndOriginalKey(t *testing.T) {
	discovery, _, _ := discoveryFixture(t)
	flowPolicy, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	devicePolicy, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	discovery.BrowserDevice.Cookie = devicePolicy
	codec, err := session.NewBrowserDeviceCodec(discovery.BrowserDevice)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(context.Background(), discovery.Now(), testTenant, "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := http.ParseSetCookie(device.CookieHeader())
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	flowToken, err := token.Reveal()
	if err != nil {
		t.Fatal(err)
	}
	flowID, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	probe := &signinStartProbe{}
	discovery.Network.Limits.MaximumFields = 16
	config := SigninStartConfig{
		Browser:    SigninBrowserConfig{Network: discovery.Network, TenantID: testTenant, Origin: "https://tenant.example", FlowCookie: flowPolicy, Device: discovery.BrowserDevice, Rate: discovery.Rate, Now: discovery.Now, MaximumDuration: time.Second},
		ProviderID: "approved-oidc", AuthorizationEndpoint: "https://provider.example/authorize",
		CallbackAllowlist: []string{"https://tenant.example/ok", "https://tenant.example/error"},
		Lifetime:          session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 15 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute},
		Start:             probe,
	}
	feature, err := NewSigninStartFeature(config)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0].Record.OperationID != "identity.sso.signin-start" {
		t.Fatal("selected start must not advertise callback or discovery")
	}
	discovery.SigninStart = &config
	combined, err := NewFeature(discovery)
	if err != nil || len(combined.Operations()) != 2 {
		t.Fatal("explicit discovery and start did not compose under the same SSO owner", err)
	}
	router, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: config.Browser.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, operations, nil)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"flowID":%q,"commandID":%q,"providerID":"approved-oidc","callback":"https://tenant.example/ok","errorCallback":"https://tenant.example/error"}`, flowID, command)
	request := func(origin, payload string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/sso/signin-start", strings.NewReader(payload))
		r.RequestURI = r.URL.RequestURI()
		r.TLS, r.RemoteAddr = &tls.ConnectionState{}, "192.0.2.17:32000"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", origin)
		r.Header.Set("Idempotency-Key", "enterprise-original-key")
		r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: flowToken})
		r.AddCookie(deviceCookie)
		return r
	}
	for _, bad := range []struct{ origin, body string }{{"https://other.example", body}, {"https://tenant.example", strings.Replace(body, "approved-oidc", "other-oidc", 1)}} {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, request(bad.origin, bad.body))
		if (w.Code != http.StatusForbidden && w.Code != http.StatusBadRequest) || probe.calls != 0 || w.Header().Get("Location") != "" {
			t.Fatal("unselected provider or origin reached native admission", w.Code)
		}
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, request("https://tenant.example", body))
	key, err := identity.NewIdempotencyKey([]byte("enterprise-original-key"))
	if err != nil {
		t.Fatal(err)
	}
	wantKey, err := key.Digest([32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	gotKey, err := probe.seen.IdempotencyKey.Digest([32]byte{9})
	if w.Code != http.StatusForbidden || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" ||
		probe.calls != 1 || probe.tenant != testTenant || probe.seen.CommandID != command || err != nil || gotKey != wantKey ||
		probe.browser.FlowID != flowID || probe.browser.Origin != "https://tenant.example" || probe.browser.FlowCookie.Token() != flowToken ||
		probe.browser.Network != netip.MustParseAddr("192.0.2.17") || probe.browser.Device == "" {
		t.Fatal("transport did not preserve exact scoped invocation and redacted denial", w.Code)
	}
	transaction, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "sso", OperationID: signinStartOperation, SchemaID: "identity.sso.signin-start.oidc-v1", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
	binding := identity.CommandBinding{CommandID: transaction, TenantID: testTenant, AnonymousFlowID: string(flowID), ActorID: "sso-login", ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "signin-policy", PolicyVersion: 1, CorrelationID: string(transaction), RecordID: string(transaction)}
	receipt := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "start-audit", Feature: &identity.FeatureReceipt{Operation: op, BeforeVersion: 0, AfterVersion: 1}}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	redirect := "https://provider.example/authorize?response_type=code&code_challenge_method=S256&state=fixture-state"
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	probe.result = sso.SigninStartResult{RedirectURI: *parsed, TransactionID: string(transaction), ProviderID: "approved-oidc", Protocol: "oidc", Completion: receipt}
	w = httptest.NewRecorder()
	router.ServeHTTP(w, request("https://tenant.example", body))
	var response struct{ AuthorizationURL, TransactionID string }
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || w.Code != http.StatusOK || response.AuthorizationURL != redirect || response.TransactionID != string(transaction) || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("start did not project only the acknowledged original authorization redirect", w.Code, err)
	}
	probe.result.RedirectURI.Host = "other-provider.example"
	w = httptest.NewRecorder()
	router.ServeHTTP(w, request("https://tenant.example", body))
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "other-provider.example") {
		t.Fatal("start disclosed a redirect outside the configured provider endpoint", w.Code)
	}
}
