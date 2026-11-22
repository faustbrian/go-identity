package ssohttp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-sso"
)

type oauth2CallbackProbe struct {
	source     SigninCallbackRateContext
	attributed []OAuth2SigninCallbackRequest
	completed  []OAuth2SigninCallbackRequest
	result     SigninCallbackResult
	err        error
}

func (p *oauth2CallbackProbe) OAuth2CallbackRateSource(_ context.Context, request OAuth2SigninCallbackRequest) (SigninCallbackRateContext, error) {
	p.attributed = append(p.attributed, request)
	return p.source, nil
}

func (p *oauth2CallbackProbe) CompleteSSOOAuth2(_ context.Context, request OAuth2SigninCallbackRequest) (SigninCallbackResult, error) {
	p.completed = append(p.completed, request)
	return p.result, p.err
}

func TestEnterpriseOAuth2CallbackPreservesNativeIssuerSettlementAndCookieCustody(t *testing.T) {
	discovery, _, _ := discoveryFixture(t)
	cookie := func(name string) session.CookiePolicy {
		t.Helper()
		policy, err := session.NewCookiePolicy(session.CookieConfig{Name: name, SameSite: http.SameSiteLaxMode})
		if err != nil {
			t.Fatal(err)
		}
		return policy
	}
	discovery.BrowserDevice.Cookie = cookie("__Host-identity_device")
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
	csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
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
	probe := &oauth2CallbackProbe{source: SigninCallbackRateContext{
		ProviderID: "approved-oauth2", FlowID: flow, TransactionID: string(command), Lifetime: time.Minute,
	}}
	config := OAuth2SigninCallbackConfig{
		Browser: SigninBrowserConfig{Network: discovery.Network, TenantID: testTenant, Origin: "https://tenant.example",
			FlowCookie: cookie("__Host-identity_flow"), Device: discovery.BrowserDevice, Rate: discovery.Rate, Now: discovery.Now, MaximumDuration: time.Second},
		ProviderID: "approved-oauth2", CallbackAllowlist: []string{"https://tenant.example/ok"}, Audience: "enterprise-app",
		Cookie: cookie("__Host-identity_session"), CSRFCookie: csrf, Callback: probe,
	}
	feature, err := NewOAuth2SigninCallbackFeature(config)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	transport := identityhttp.TransportPolicy{Network: discovery.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}
	router, doc, err := identityhttp.NewRouter(transport, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	base, baseDoc, err := identityhttp.NewRouter(transport, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	const path = "/sso/oauth2/callback"
	if !strings.Contains(string(doc.JSON()), path) || strings.Contains(string(baseDoc.JSON()), path) {
		t.Fatal("OAuth2 callback OpenAPI did not track explicit selection")
	}
	serve := func(h http.Handler, query, origin string, includeFlow bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://tenant.example"+path+"?"+query, nil)
		r.RequestURI = r.URL.RequestURI()
		r.RemoteAddr = "192.0.2.17:32000"
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if includeFlow {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
		}
		r.AddCookie(deviceCookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	assertNoDelivery := func(w *httptest.ResponseRecorder, status int) {
		t.Helper()
		if w.Code != status || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" ||
			strings.Contains(w.Body.String(), "fixture-oauth2-code") {
			t.Fatal("unexpected response or credential delivery", w.Code)
		}
	}
	query := "state=" + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + "&code=fixture-oauth2-code"
	assertNoDelivery(serve(base, query, "", true), http.StatusNotFound)
	assertNoDelivery(serve(router, query, "https://wrong.example", true), http.StatusForbidden)
	assertNoDelivery(serve(router, query, "", false), http.StatusForbidden)
	assertNoDelivery(serve(router, query+"&i%73s=%ZZ&Idempotency%2DKey=foreign", "", true), http.StatusBadRequest)
	if len(probe.attributed) != 0 || len(probe.completed) != 0 {
		t.Fatal("unselected or unauthenticated callback reached native custody")
	}
	probe.err = sso.ErrForbidden
	badIssuer := query + "&iss=%ZZ"
	assertNoDelivery(serve(router, badIssuer, "", true), http.StatusForbidden)
	if len(probe.attributed) != 1 || len(probe.completed) != 1 {
		t.Fatal("the original authenticated browser did not reach native refusal")
	}
	first, completed := probe.attributed[0], probe.completed[0]
	if first.RawQuery != badIssuer || completed.RawQuery != badIssuer || first.Browser.FlowID != "" || completed.Browser.FlowID != flow ||
		completed.TenantID != testTenant || completed.ReceivedRedirectURI != "https://tenant.example/sso/oauth2/callback" {
		t.Fatal("HTTP rewrote native issuer or original browser custody")
	}
	query += "&iss=https%3A%2F%2Fprovider.example"
	probe.err = nil
	fixture := SigninCallbackConfig{Browser: config.Browser, Audience: config.Audience, Cookie: config.Cookie, CSRFCookie: config.CSRFCookie, CallbackAllowlist: config.CallbackAllowlist}
	probe.result = enterpriseIssueFixture(t, fixture, flow, command)
	assertNoDelivery(serve(router, query, "", true), http.StatusServiceUnavailable)
	op := identity.FeatureOperation{Owner: "sso/oauth2", OperationID: "identity.sso.oauth-callback", SchemaID: "sso-enterprise-oauth2-callback-v1", SchemaVersion: 1,
		SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
	probe.result = enterpriseIssueFixtureForOperation(t, fixture, flow, command, op, "sso-oauth2")
	w := serve(router, query, "", true)
	response := w.Result()
	defer response.Body.Close()
	cookies := response.Cookies()
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != config.CallbackAllowlist[0] || w.Header().Get("Cache-Control") != "no-store" ||
		len(cookies) != 2 || cookies[0].Name != "__Host-identity_session" || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[1].Name != "__Host-identity_csrf" || !cookies[1].Secure || cookies[1].HttpOnly {
		t.Fatal("acknowledged native OAuth2 callback did not deliver the scoped redirect and cookies", w.Code)
	}
	probe.result.Issuance.Replayed = true
	assertNoDelivery(serve(router, query, "", true), http.StatusServiceUnavailable)
	probe.err = identity.UnknownCommitError{CommandID: command}
	assertNoDelivery(serve(router, query, "", true), http.StatusServiceUnavailable)
	before := len(probe.completed)
	w = serve(router, query, "", true)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || len(probe.completed) != before {
		t.Fatal("transaction quota did not run before native completion", w.Code)
	}
	assertNoDelivery(w, http.StatusTooManyRequests)
}

func FuzzOAuth2CallbackCredentialViewKeepsNonIssuerFields(f *testing.F) {
	for _, seed := range []string{"", "%ZZ", "https%3A%2F%2Fidp.example", "&idempotency_key=foreign", "x%26identity_flow"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, issuer string) {
		if len(issuer) > 1024 || strings.ContainsAny(issuer, "\r\n#") {
			t.Skip()
		}
		raw := "state=bound&iss=one&i%73s=" + issuer + "&code=two"
		r := &http.Request{URL: &url.URL{Path: oauth2SigninCallbackPath, RawQuery: raw}, RequestURI: oauth2SigninCallbackPath + "?" + raw}
		view := oauth2CallbackCredentialRequest(r)
		if view == r || view.URL == r.URL || view.URL.Path != r.URL.Path || r.URL.RawQuery != raw || r.RequestURI != oauth2SigninCallbackPath+"?"+raw {
			t.Fatal("credential view mutated the original callback target")
		}
		want := "state=bound&code=two"
		if !strings.Contains(issuer, "&") && view.URL.RawQuery != want {
			t.Fatal("credential view did not discard both exact decoded issuer fields")
		}
		if strings.Contains(issuer, "&idempotency_key=foreign") && !strings.Contains(view.URL.RawQuery, "idempotency_key=foreign") {
			t.Fatal("credential view suppressed a separate idempotency field")
		}
		if view.RequestURI != view.URL.RequestURI() {
			t.Fatal("credential view did not preserve request framing consistency")
		}
	})
}
