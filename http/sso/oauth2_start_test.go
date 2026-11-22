package ssohttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

type oauth2StartProbe struct{ signinStartProbe }

func (p *oauth2StartProbe) StartSSOOAuth2(ctx context.Context, tenant identity.TenantID, request sso.SigninStartRequest, browser SigninBrowser) (sso.SigninStartResult, error) {
	return p.signinStartProbe.StartSSOOIDC(ctx, tenant, request, browser)
}

func TestEnterpriseSigninStartDispatchesOnlyConfiguredProtocol(t *testing.T) {
	discovery, _, _ := discoveryFixture(t)
	discovery.Network.Limits.MaximumFields = 16
	flowCookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	discovery.BrowserDevice.Cookie, err = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	codec, err := session.NewBrowserDeviceCodec(discovery.BrowserDevice)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(t.Context(), discovery.Now(), testTenant, "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	deviceCookie, err := http.ParseSetCookie(device.CookieHeader())
	if err != nil {
		t.Fatal(err)
	}
	flow, err := identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	callbacks := []string{"https://tenant.example/ok", "https://tenant.example/error"}
	browser := SigninBrowserConfig{Network: discovery.Network, TenantID: testTenant, Origin: "https://tenant.example", FlowCookie: flowCookie,
		Device: discovery.BrowserDevice, Rate: discovery.Rate, Now: discovery.Now, MaximumDuration: time.Second}
	lifetime := session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 15 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}
	const oidcID = "enterprise-oidc"
	const oauth2ID = "enterprise-oauth2"
	const oidcEndpoint = "https://oidc.example/authorize"
	const oauth2Endpoint = "https://oauth.example/authorize"
	oidc := &signinStartProbe{result: enterpriseTestStartResult(t, oidcID, "oidc", oidcEndpoint, flow)}
	plain := &oauth2StartProbe{signinStartProbe{result: enterpriseTestStartResult(t, oauth2ID, "oauth2", oauth2Endpoint, flow)}}
	oidcConfig := SigninStartConfig{Browser: browser, Lifetime: lifetime, ProviderID: oidcID, AuthorizationEndpoint: oidcEndpoint, CallbackAllowlist: callbacks, Start: oidc}
	oauth2Config := OAuth2SigninStartConfig{ProviderID: oauth2ID, AuthorizationEndpoint: oauth2Endpoint, CallbackAllowlist: callbacks, Start: plain}
	makeRouter := func(f identityhttp.Feature, err error) (http.Handler, identityhttp.OpenAPIDocument) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
		if err != nil {
			t.Fatal(err)
		}
		h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: browser.Network, HandlerTimeout: time.Second,
			Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
		if err != nil {
			t.Fatal(err)
		}
		return h, doc
	}
	serve := func(h http.Handler, provider, extra string) *httptest.ResponseRecorder {
		body := fmt.Sprintf(`{"flowID":%q,"commandID":%q,"providerID":%q,"callback":%q,"errorCallback":%q%s}`, flow, command, provider, callbacks[0], callbacks[1], extra)
		r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/sso/signin-start", strings.NewReader(body))
		r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "192.0.2.17:32000"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://tenant.example")
		r.Header.Set("Idempotency-Key", "identity-placed-start-key")
		r.AddCookie(deviceCookie)
		r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	exactResult := func(w *httptest.ResponseRecorder, selected sso.SigninStartResult) {
		t.Helper()
		var got struct{ AuthorizationURL, Protocol, ProviderID string }
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK ||
			got.Protocol != selected.Protocol || got.ProviderID != selected.ProviderID || got.AuthorizationURL != selected.RedirectURI.String() ||
			w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" {
			t.Fatal("start did not disclose only the selected, acknowledged authorization redirect", w.Code, err)
		}
	}
	onlyPlain, plainDoc := makeRouter(NewOAuth2SigninStartFeature(browser, lifetime, oauth2Config))
	if w := serve(onlyPlain, oidcID, ""); w.Code != http.StatusBadRequest || plain.calls != 0 || oidc.calls != 0 {
		t.Fatal("OAuth2-only selection dispatched another provider", w.Code)
	}
	const exactDomain = `,"domain":"example.com"`
	if w := serve(onlyPlain, oauth2ID, ""); w.Code != http.StatusBadRequest || plain.calls != 0 {
		t.Fatal("OAuth2 selection reached the owner without the required domain", w.Code)
	}
	exactResult(serve(onlyPlain, oauth2ID, exactDomain), plain.result)
	if !strings.Contains(string(plainDoc.JSON()), `"const":"oauth2"`) || strings.Contains(string(plainDoc.JSON()), `"const":"oidc"`) ||
		!strings.Contains(string(plainDoc.JSON()), `"required":["flowID","commandID","providerID","callback","errorCallback","domain"]`) {
		t.Fatal("OAuth2-only OpenAPI did not match provider selection and required domain")
	}
	mixed, mixedDoc := makeRouter(NewSigninStartFeatureWithOAuth2(oidcConfig, oauth2Config, nil))
	exactResult(serve(mixed, oidcID, ""), oidc.result)
	exactResult(serve(mixed, oauth2ID, exactDomain), plain.result)
	if plain.calls != 2 || oidc.calls != 1 || plain.browser.FlowID != flow || plain.tenant != testTenant ||
		plain.seen.CommandID != command || plain.seen.ProviderID != oauth2ID || plain.seen.Domain != "example.com" || !strings.Contains(string(mixedDoc.JSON()), `"enum":["oidc","oauth2"]`) {
		t.Fatal("mixed start did not preserve configured owner and original browser flow")
	}
	if w := serve(mixed, oauth2ID, exactDomain+`,"protocol":"oidc"`); w.Code != http.StatusBadRequest || plain.calls != 2 || oidc.calls != 1 {
		t.Fatal("a caller-supplied protocol selected authority", w.Code)
	}
	plain.result.Protocol = "oidc"
	if w := serve(mixed, oauth2ID, exactDomain); w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("OAuth2 selection accepted the wrong protocol receipt", w.Code)
	}
	oauth2Config.ProviderID = oidcID
	if _, err := NewSigninStartFeatureWithOAuth2(oidcConfig, oauth2Config, nil); err == nil {
		t.Fatal("the same provider ID cannot select two protocols")
	}
}

func enterpriseTestStartResult(t *testing.T, provider, protocol, endpoint string, flow identity.PreAuthTransactionID) sso.SigninStartResult {
	t.Helper()
	tx, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "sso", OperationID: signinStartOperation, SchemaID: "identity.sso.signin-start." + protocol + "-v1", SchemaVersion: 1,
		SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
	binding := identity.CommandBinding{CommandID: tx, TenantID: testTenant, AnonymousFlowID: string(flow), ActorID: "native-sso-login",
		ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1,
		PolicyID: "signin-policy", PolicyVersion: 1, CorrelationID: string(tx), RecordID: string(tx)}
	result := identity.CommandResult{Binding: binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "start-audit",
		Feature: &identity.FeatureReceipt{Operation: op, BeforeVersion: 0, AfterVersion: 1}}
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(endpoint + "?response_type=code&code_challenge_method=S256&state=fixture-state")
	if err != nil {
		t.Fatal(err)
	}
	return sso.SigninStartResult{RedirectURI: *redirect, TransactionID: string(tx), ProviderID: provider, Protocol: protocol, Completion: result}
}
