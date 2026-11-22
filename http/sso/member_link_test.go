package ssohttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

func FuzzEnterpriseMemberLinkMode(f *testing.F) {
	f.Add("true", false, false)
	f.Add("false", false, false)
	f.Add(`"true"`, false, false)
	f.Add("null", false, false)
	f.Add("true", true, false)
	f.Add("true", false, true)
	f.Fuzz(func(t *testing.T, value string, duplicate, mixedFlow bool) {
		if len(value) > 256 || !json.Valid([]byte(value)) {
			return
		}
		browser, auth, device := memberLinkTransportFixture(t)
		browser.Network.Limits.MaximumFields = 16
		command, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		member, signin := &memberStartProbe{}, &signinStartProbe{}
		config := SigninStartConfig{Browser: browser, ProviderID: "approved-oidc", AuthorizationEndpoint: "https://provider.example/authorize",
			CallbackAllowlist: []string{"https://tenant.example/ok"}, Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour,
				IdleTTL: 15 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, Start: signin}
		feature, err := NewSigninStartFeatureWithLink(config, MemberLinkStartConfig{Cookie: auth, Start: member})
		if err != nil {
			t.Fatal(err)
		}
		input := fmt.Sprintf(`"link":%s,"commandID":%q,"providerID":"approved-oidc","callback":"https://tenant.example/ok","errorCallback":"https://tenant.example/ok"`, value, command)
		if duplicate {
			input += `,"link":true`
		}
		if mixedFlow {
			flow, err := identity.NewPreAuthTransactionID()
			if err != nil {
				t.Fatal(err)
			}
			input += fmt.Sprintf(`,"flowID":%q`, flow)
		}
		r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/sso/signin-start", strings.NewReader("{"+input+"}"))
		r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "192.0.2.17:32000"
		r.Header.Set("Origin", "https://tenant.example")
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "member-start-mode")
		r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43))
		r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: strings.Repeat("A", 43)})
		r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
		r.AddCookie(device)
		response := httptest.NewRecorder()
		memberLinkHandler(t, browser, feature).ServeHTTP(response, r)
		wantLink := strings.Trim(value, " \t\n\r") == "true" && !duplicate && !mixedFlow
		if (member.calls == 1) != wantLink || member.calls > 1 || signin.calls != 0 {
			t.Fatal("invalid or mixed input selected a native owner")
		}
	})
}

func TestEnterpriseMemberStartRequiresLocalCookieAndCSRF(t *testing.T) {
	browser, authCookie, device := memberLinkTransportFixture(t)
	browser.Network.Limits.MaximumFields = 16
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	owner := &memberStartProbe{}
	legacy := &signinStartProbe{}
	config := SigninStartConfig{Browser: browser, ProviderID: "approved-oidc", AuthorizationEndpoint: "https://provider.example/authorize",
		CallbackAllowlist: []string{"https://tenant.example/ok"}, Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour,
			IdleTTL: 15 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, Start: legacy}
	feature, err := NewSigninStartFeatureWithLink(config, MemberLinkStartConfig{Cookie: authCookie, Start: owner})
	if err != nil {
		t.Fatal(err)
	}
	router := memberLinkHandler(t, browser, feature)
	wire := strings.Repeat("A", 43)
	body := fmt.Sprintf(`{"link":true,"commandID":%q,"providerID":"approved-oidc","callback":"https://tenant.example/ok","errorCallback":"https://tenant.example/ok"}`, command)
	serve := func(origin, csrf string, cookie bool, body string) int {
		r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/sso/signin-start", strings.NewReader(body))
		r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "192.0.2.17:32000"
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "member-start-request")
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		if cookie {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: wire})
		}
		r.AddCookie(device)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w.Code
	}
	for _, got := range []int{
		serve("https://tenant.example", "", true, body),
		serve("https://other.example", wire, true, body),
		serve("https://tenant.example", wire, false, body),
		serve("https://tenant.example", wire, true, strings.Replace(body, `"link":true`, `"link":true,"remember":true`, 1)),
	} {
		if got != http.StatusForbidden && got != http.StatusBadRequest {
			t.Fatalf("denial status = %d", got)
		}
	}
	if owner.calls != 0 || legacy.calls != 0 {
		t.Fatal("incomplete consent reached a native owner")
	}
	if got := serve("https://tenant.example", wire, true, body); got != http.StatusForbidden || owner.calls != 1 || legacy.calls != 0 {
		t.Fatalf("complete consent did not reach only the member owner: status=%d member=%d legacy=%d", got, owner.calls, legacy.calls)
	}
	op := identity.FeatureOperation{Owner: "sso", OperationID: signinStartOperation, SchemaID: "identity.sso.signin-start.oidc-link-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	bound := identity.CommandBinding{CommandID: command, TenantID: testTenant, UserID: "member", ActorID: "member", ActorKind: authorization.SubjectUser,
		OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, PolicyID: "signin-policy", PolicyVersion: 1, CorrelationID: string(command), RecordID: string(command)}
	redirect, err := url.Parse("https://provider.example/authorize?response_type=code")
	if err != nil {
		t.Fatal(err)
	}
	owner.result = sso.SigninStartResult{RedirectURI: *redirect, TransactionID: string(command), ProviderID: config.ProviderID, Protocol: "oidc",
		Completion: identity.CommandResult{Binding: bound, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "start-audit", Feature: &identity.FeatureReceipt{Operation: op, AfterVersion: 1}}}
	if got := serve("https://tenant.example", wire, true, body); got != http.StatusOK || owner.calls != 2 || legacy.calls != 0 {
		t.Fatalf("acknowledged member start not delivered: status=%d member=%d legacy=%d", got, owner.calls, legacy.calls)
	}
}

type memberStartProbe struct {
	calls  int
	result sso.SigninStartResult
}

func (p *memberStartProbe) StartSSOOIDCLink(_ context.Context, tenant identity.TenantID, request sso.SigninStartRequest, browser SigninBrowser,
	cookie authentication.BearerCredential, csrf session.CSRFToken,
) (sso.SigninStartResult, error) {
	if tenant == testTenant && request.ProviderID == "approved-oidc" && browser.FlowID == "" && cookie.Token() != "" && csrf != (session.CSRFToken{}) {
		p.calls++
		if p.result.Completion.Outcome == identity.CommitOutcomeCommitted {
			return p.result, nil
		}
	}
	return sso.SigninStartResult{}, sso.ErrForbidden
}

func TestEnterpriseSharedCallbackDoesNotFallbackOrDeliverCookiesForLink(t *testing.T) {
	browser, authCookie, device := memberLinkTransportFixture(t)
	csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	legacy := &signinCallbackProbe{}
	member := &memberCallbackProbe{}
	member.command, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	config := SigninCallbackConfig{Browser: browser, Cookie: authCookie, CSRFCookie: csrf, Audience: "enterprise-app", Callback: legacy,
		CallbackAllowlist: []string{"https://tenant.example/ok"}, Provider: oauth.ProviderProfile{ID: "approved-oidc", Version: 1,
			Issuer: "https://provider.example", AuthorizationEndpoint: "https://provider.example/authorize", TokenEndpoint: "https://provider.example/token",
			RedirectURI: "https://tenant.example/sso/oidc/callback", ClientID: "transport-client", ClientAuthentication: oauth.ClientSecretBasic,
			Scopes: []string{"openid"}, Algorithms: []string{"ES256"}, ResponseMode: "query", PKCEMethod: "S256", NonceRequired: true,
			StateBytes: 32, NonceBytes: 32, Timeout: time.Second, ClockSkew: time.Second, MaxResponseBytes: 4096, MaxTokenBytes: 1024, MaxCodeBytes: 512}}
	feature, err := NewSigninCallbackFeatureWithLink("approved-oidc", config, member)
	if err != nil {
		t.Fatal(err)
	}
	router := memberLinkHandler(t, browser, feature)
	query := url.Values{"code": {"fixture-authorization-code"}, "state": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, "iss": {"https://provider.example"}}.Encode()
	serve := func(flow, cookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://tenant.example/sso/oidc/callback?"+query, nil)
		r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "192.0.2.17:32000"
		if flow {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
		}
		if cookie {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: strings.Repeat("A", 43)})
		}
		r.AddCookie(device)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if denied := serve(true, false); denied.Code != http.StatusForbidden || denied.Header().Get("Location") != "" || member.calls != 0 || legacy.calls != 0 || legacy.attributions != 0 {
		t.Fatalf("failed member attribution fell back to anonymous: %d", denied.Code)
	}
	success := serve(false, true)
	if success.Code != http.StatusSeeOther || success.Header().Get("Location") != "https://tenant.example/ok" || len(success.Header().Values("Set-Cookie")) != 0 || member.calls != 1 || legacy.calls != 0 || legacy.attributions != 0 {
		t.Fatalf("member callback did not redirect without session delivery: status=%d member=%d legacy=%d", success.Code, member.calls, legacy.calls)
	}
	member.flow, err = identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	member.command, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	legacy.result = enterpriseIssueFixture(t, config, member.flow, member.command)
	signin := serve(true, true)
	if signin.Code != http.StatusSeeOther || len(signin.Header().Values("Set-Cookie")) != 2 || member.calls != 1 || legacy.calls != 1 || legacy.request.Browser.FlowID != member.flow {
		t.Fatalf("stored sign-in with both cookies did not issue its session: status=%d member=%d legacy=%d", signin.Code, member.calls, legacy.calls)
	}
	member.command, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	legacy.result = enterpriseIssueFixture(t, config, member.flow, member.command)
	signin = serve(true, false)
	if signin.Code != http.StatusSeeOther || len(signin.Header().Values("Set-Cookie")) != 2 || member.calls != 1 || legacy.calls != 2 || legacy.request.Browser.FlowID != member.flow {
		t.Fatalf("stored sign-in without a member cookie did not issue its session: status=%d member=%d legacy=%d", signin.Code, member.calls, legacy.calls)
	}
}

type memberCallbackProbe struct {
	command identity.CommandID
	flow    identity.PreAuthTransactionID
	calls   int
}

func (p *memberCallbackProbe) SharedCallbackRateSource(_ context.Context, request SigninCallbackRequest, cookie authentication.BearerCredential) (SharedCallbackRateContext, error) {
	if p.flow == "" && cookie.Token() == "" || p.flow != "" && request.Browser.FlowCookie.Token() == "" {
		return SharedCallbackRateContext{}, identity.ForbiddenError{}
	}
	return SharedCallbackRateContext{SigninCallbackRateContext: SigninCallbackRateContext{ProviderID: "approved-oidc", FlowID: p.flow, TransactionID: string(p.command), Lifetime: time.Minute}, MemberLink: p.flow == ""}, nil
}
func (p *memberCallbackProbe) CompleteSSOOIDCLink(context.Context, SigninCallbackRequest, authentication.BearerCredential) (MemberLinkCallbackResult, error) {
	p.calls++
	return MemberLinkCallbackResult{CommandID: p.command, RedirectURI: "https://tenant.example/ok"}, nil
}

func memberLinkTransportFixture(t *testing.T) (SigninBrowserConfig, session.CookiePolicy, *http.Cookie) {
	t.Helper()
	discovery, _, _ := discoveryFixture(t)
	flow, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
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
	auth, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	return SigninBrowserConfig{Network: discovery.Network, TenantID: testTenant, Origin: "https://tenant.example", FlowCookie: flow,
		Device: discovery.BrowserDevice, Rate: discovery.Rate, Now: discovery.Now, MaximumDuration: time.Second}, auth, deviceCookie
}

func memberLinkHandler(t *testing.T, browser SigninBrowserConfig, feature identityhttp.Feature) http.Handler {
	t.Helper()
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	h, _, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: browser.Network, HandlerTimeout: time.Second,
		Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, operations, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
