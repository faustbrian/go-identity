package ssohttp

import (
	"context"
	"encoding/base64"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
)

const (
	samlLogoutHTTPOrigin   = "https://tenant.example"
	samlLogoutHTTPIDP      = "https://idp.example"
	samlLogoutHTTPProvider = "-installed"
	samlLogoutHTTPPath     = "/saml2/" + samlLogoutHTTPProvider + "/slo"
	samlLogoutHTTPEndpoint = samlLogoutHTTPIDP + "/logout?binding=post&profile=selected"
	samlLogoutHTTPFinish   = samlLogoutHTTPOrigin + "/signed-out"
)

type samlLogoutHTTPProbe struct {
	request  func(context.Context, SAMLLogoutRequest) (SAMLLogoutRequestResult, error)
	response func(context.Context, SAMLLogoutResponseRequest) (SAMLLogoutResponseResult, error)
}

func (p *samlLogoutHTTPProbe) HandleSAMLLogoutRequest(ctx context.Context, r SAMLLogoutRequest) (SAMLLogoutRequestResult, error) {
	return p.request(ctx, r)
}

func (p *samlLogoutHTTPProbe) SettleSAMLLogoutResponse(ctx context.Context, r SAMLLogoutResponseRequest) (SAMLLogoutResponseResult, error) {
	return p.response(ctx, r)
}

type samlLogoutHTTPFixture struct {
	config                      SAMLLogoutConfig
	owner                       *samlLogoutHTTPProbe
	router                      http.Handler
	document                    identityhttp.OpenAPIDocument
	requestWire, responseWire   string
	signedResponse              string
	requestCalls, responseCalls int
}

func newSAMLLogoutHTTPFixture(t *testing.T) *samlLogoutHTTPFixture {
	t.Helper()
	discovery, _, _ := discoveryFixture(t)
	f := &samlLogoutHTTPFixture{
		requestWire:    base64.StdEncoding.EncodeToString([]byte("<native-validated-logout-request/>")),
		responseWire:   base64.StdEncoding.EncodeToString([]byte("<native-validated-logout-response/>")),
		signedResponse: base64.StdEncoding.EncodeToString([]byte("<native-signed-logout-response/>")),
	}
	f.owner = &samlLogoutHTTPProbe{}
	f.config = SAMLLogoutConfig{Network: discovery.Network, TenantID: testTenant, Origin: samlLogoutHTTPOrigin,
		IdentityProviderOrigin: samlLogoutHTTPIDP, ProviderID: samlLogoutHTTPProvider,
		ResponseEndpoint: samlLogoutHTTPEndpoint, FinalRedirectAllowlist: []string{samlLogoutHTTPFinish},
		Rate: discovery.Rate, MaximumDuration: time.Second, Owner: f.owner}
	f.config.Network.TenantHosts = append(f.config.Network.TenantHosts, identityhttp.TenantHost{Host: "alias.example", TenantID: testTenant})
	checkContext := func(ctx context.Context) {
		t.Helper()
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > f.config.MaximumDuration {
			t.Fatal("SAML logout owner did not receive the bounded live request context")
		}
	}
	f.owner.request = func(ctx context.Context, r SAMLLogoutRequest) (SAMLLogoutRequestResult, error) {
		checkContext(ctx)
		f.requestCalls++
		if r.TenantID != testTenant || r.ProviderID != samlLogoutHTTPProvider || r.SAMLRequest != f.requestWire {
			t.Fatal("logout request changed exact tenant/provider or original Base64 wire")
		}
		return SAMLLogoutRequestResult{Destination: samlLogoutHTTPEndpoint, SAMLResponse: f.signedResponse}, nil
	}
	f.owner.response = func(ctx context.Context, r SAMLLogoutResponseRequest) (SAMLLogoutResponseResult, error) {
		checkContext(ctx)
		f.responseCalls++
		if r.TenantID != testTenant || r.ProviderID != samlLogoutHTTPProvider || r.SAMLResponse != f.responseWire {
			t.Fatal("logout response changed exact tenant/provider or original Base64 wire")
		}
		return SAMLLogoutResponseResult{FinalRedirect: samlLogoutHTTPFinish}, nil
	}
	f.rebuild(t)
	return f
}

func (f *samlLogoutHTTPFixture) rebuild(t *testing.T) {
	t.Helper()
	op, err := NewSAMLLogoutOperation(f.config)
	if err != nil {
		t.Fatal("select installed SAML logout transport", err)
	}
	f.router, f.document, err = identityhttp.NewRouter(identityhttp.TransportPolicy{
		Network: f.config.Network, HandlerTimeout: time.Second,
		CORS:     []identityhttp.CORSRoutePolicy{f.config.NavigationPolicy()},
		Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"},
	}, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal("compose SAML logout through the canonical router", err)
	}
}

func (f *samlLogoutHTTPFixture) request(field string) *http.Request {
	wire := f.requestWire
	if field == "SAMLResponse" {
		wire = f.responseWire
	}
	return f.formRequest(url.Values{field: {wire}}.Encode())
}

func (f *samlLogoutHTTPFixture) formRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, samlLogoutHTTPOrigin+samlLogoutHTTPPath, strings.NewReader(body))
	r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "192.0.2.17:32000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", samlLogoutHTTPIDP)
	return r
}

func (f *samlLogoutHTTPFixture) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func assertSAMLLogoutHTTPNoBrowserAuthority(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Access-Control-Allow-Origin") != "" ||
		w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("SAML logout created cookie or script authority")
	}
}

func assertSAMLLogoutHTTPDenied(t *testing.T, f *samlLogoutHTTPFixture, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	assertSAMLLogoutHTTPNoBrowserAuthority(t, w)
	if w.Code != status || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "<form") ||
		strings.Contains(w.Body.String(), f.requestWire) || strings.Contains(w.Body.String(), f.responseWire) ||
		strings.Contains(w.Body.String(), f.signedResponse) {
		t.Fatalf("denial leaked logout wire or returned %d instead of %d", w.Code, status)
	}
}

func TestSAMLLogoutHTTPReturnsOnlyExplicitSignedResponseForm(t *testing.T) {
	f := newSAMLLogoutHTTPFixture(t)
	r := f.request("SAMLRequest")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "ambient-session-not-authority"})
	w := f.serve(r)
	assertSAMLLogoutHTTPNoBrowserAuthority(t, w)
	if w.Code != http.StatusOK || w.Header().Get("Location") != "" || f.requestCalls != 1 || f.responseCalls != 0 ||
		!strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") || w.Header().Get("Cache-Control") != "no-store" ||
		w.Header().Get("Referrer-Policy") != "no-referrer" || !strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action "+samlLogoutHTTPIDP+";") {
		t.Fatal("validated IdP logout did not produce only a private response document", w.Code)
	}
	body := w.Body.String()
	lower := strings.ToLower(body)
	for _, forbidden := range []string{"<script", "onload", "onsubmit", "http-equiv", "autofocus", "relaystate", "ambient-session-not-authority", strings.ToLower(f.requestWire)} {
		if strings.Contains(lower, forbidden) {
			t.Fatal("response document leaked input custody or navigated automatically", forbidden)
		}
	}
	attrs := regexp.MustCompile(`\s([a-z]+)="([^"]*)"`)
	attributes := func(tag string) map[string]string {
		out := make(map[string]string)
		for _, match := range attrs.FindAllStringSubmatch(tag, -1) {
			out[match[1]] = html.UnescapeString(match[2])
		}
		return out
	}
	forms := regexp.MustCompile(`<form\b[^>]*>`).FindAllString(body, -1)
	if len(forms) != 1 {
		t.Fatal("logout response must contain exactly one explicit submission form")
	}
	form := attributes(forms[0])
	if form["action"] != samlLogoutHTTPEndpoint || strings.ToLower(form["method"]) != "post" ||
		!strings.Contains(body, "&amp;profile=selected") || !strings.Contains(lower, "<button") {
		t.Fatal("response form did not escape the exact configured IdP endpoint or require user submission")
	}
	hidden := make(url.Values)
	for _, input := range regexp.MustCompile(`<input\b[^>]*>`).FindAllString(body, -1) {
		field := attributes(input)
		if field["type"] == "hidden" {
			hidden.Add(field["name"], field["value"])
		}
	}
	if len(hidden) != 1 || len(hidden["SAMLResponse"]) != 1 || hidden.Get("SAMLResponse") != f.signedResponse {
		t.Fatal("response form did not preserve exactly the native signed Base64 response")
	}
}

func TestSAMLLogoutHTTPSettlesOnlyAllowlistedContinuationAndSafeEmptyResults(t *testing.T) {
	t.Run("original allowlisted continuation", func(t *testing.T) {
		f := newSAMLLogoutHTTPFixture(t)
		w := f.serve(f.request("SAMLResponse"))
		assertSAMLLogoutHTTPNoBrowserAuthority(t, w)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != samlLogoutHTTPFinish || f.requestCalls != 0 || f.responseCalls != 1 ||
			strings.Contains(w.Body.String(), f.responseWire) || strings.Contains(w.Body.String(), f.signedResponse) {
			t.Fatal("settled native response did not select only its allowlisted SP continuation", w.Code)
		}
	})
	for _, field := range []string{"SAMLRequest", "SAMLResponse"} {
		t.Run(field+" no new wire", func(t *testing.T) {
			f := newSAMLLogoutHTTPFixture(t)
			f.owner.request = func(context.Context, SAMLLogoutRequest) (SAMLLogoutRequestResult, error) {
				return SAMLLogoutRequestResult{}, nil
			}
			f.owner.response = func(context.Context, SAMLLogoutResponseRequest) (SAMLLogoutResponseResult, error) {
				return SAMLLogoutResponseResult{}, nil
			}
			w := f.serve(f.request(field))
			assertSAMLLogoutHTTPDenied(t, f, w, http.StatusNoContent)
			if w.Body.Len() != 0 {
				t.Fatal("safe settled replay/empty result must not create another response document")
			}
		})
	}
}

func TestSAMLLogoutHTTPRejectsClosedFormBeforeNativeWork(t *testing.T) {
	for _, tc := range []struct {
		name string
		body func(*samlLogoutHTTPFixture) string
	}{
		{"empty", func(*samlLogoutHTTPFixture) string { return "" }},
		{"empty request", func(*samlLogoutHTTPFixture) string { return "SAMLRequest=" }},
		{"empty response", func(*samlLogoutHTTPFixture) string { return "SAMLResponse=" }},
		{"mixed branches", func(f *samlLogoutHTTPFixture) string {
			return url.Values{"SAMLRequest": {f.requestWire}, "SAMLResponse": {f.responseWire}}.Encode()
		}},
		{"duplicate request", func(f *samlLogoutHTTPFixture) string {
			return url.Values{"SAMLRequest": {f.requestWire, f.requestWire}}.Encode()
		}},
		{"duplicate response", func(f *samlLogoutHTTPFixture) string {
			return url.Values{"SAMLResponse": {f.responseWire, f.responseWire}}.Encode()
		}},
		{"relay state", func(f *samlLogoutHTTPFixture) string {
			return url.Values{"SAMLRequest": {f.requestWire}, "RelayState": {"unselected"}}.Encode()
		}},
		{"caller redirect", func(f *samlLogoutHTTPFixture) string {
			return url.Values{"SAMLResponse": {f.responseWire}, "finalRedirect": {samlLogoutHTTPFinish}}.Encode()
		}},
		{"public session selector", func(f *samlLogoutHTTPFixture) string {
			return url.Values{"SAMLRequest": {f.requestWire}, "sessionID": {"public-selector"}}.Encode()
		}},
		{"wrong case", func(f *samlLogoutHTTPFixture) string { return url.Values{"samlrequest": {f.requestWire}}.Encode() }},
		{"malformed encoding", func(*samlLogoutHTTPFixture) string { return "SAMLRequest=%ZZ" }},
		{"invalid Base64", func(*samlLogoutHTTPFixture) string { return "SAMLRequest=not-base64!" }},
		{"empty decoded response", func(*samlLogoutHTTPFixture) string { return "SAMLResponse=====" }},
		{"double encoded wire", func(f *samlLogoutHTTPFixture) string {
			return "SAMLRequest=" + url.QueryEscape(url.QueryEscape(f.requestWire))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSAMLLogoutHTTPFixture(t)
			assertSAMLLogoutHTTPDenied(t, f, f.serve(f.formRequest(tc.body(f))), http.StatusBadRequest)
			if f.requestCalls != 0 || f.responseCalls != 0 {
				t.Fatal("invalid or ambiguous form reached a native logout operation")
			}
		})
	}
}

func TestSAMLLogoutHTTPRequiresExactInstalledHTTPSNavigation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		mutate func(*http.Request)
	}{
		{"foreign origin", 403, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }},
		{"SP origin", 403, func(r *http.Request) { r.Header.Set("Origin", samlLogoutHTTPOrigin) }},
		{"absent origin", 403, func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Referer", samlLogoutHTTPIDP+"/logout") }},
		{"opaque origin", 403, func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"duplicate origin", 400, func(r *http.Request) { r.Header.Add("Origin", samlLogoutHTTPIDP) }},
		{"same tenant alias", 403, func(r *http.Request) { r.Host = "alias.example" }},
		{"other tenant", 403, func(r *http.Request) { r.Host = "other.example" }},
		{"public realm", 403, func(r *http.Request) { r.Host = "public.example" }},
		{"plain HTTP", 403, func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }},
		{"query", 400, func(r *http.Request) { r.URL.RawQuery = "RelayState=ignored"; r.RequestURI = r.URL.RequestURI() }},
		{"idempotency", 400, func(r *http.Request) { r.Header.Set("Idempotency-Key", "not-a-logout-authority") }},
		{"authorization", 400, func(r *http.Request) { r.Header.Set("Authorization", "Bearer not-a-logout-authority") }},
		{"proxy authorization", 400, func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer not-a-logout-authority") }},
		{"ambient CSRF", 400, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "not-a-logout-authority") }},
		{"wrong content type", 400, func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }},
		{"unselected provider", 403, func(r *http.Request) { r.URL.Path = "/saml2/unselected/slo"; r.RequestURI = r.URL.RequestURI() }},
		{"preflight", 403, func(r *http.Request) {
			r.Method = http.MethodOptions
			r.Header.Set("Access-Control-Request-Method", http.MethodPost)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSAMLLogoutHTTPFixture(t)
			r := f.request("SAMLRequest")
			tc.mutate(r)
			assertSAMLLogoutHTTPDenied(t, f, f.serve(r), tc.status)
			if f.requestCalls != 0 || f.responseCalls != 0 {
				t.Fatal("alternate origin, route, tenant or credential reached the native owner")
			}
		})
	}
}

func TestSAMLLogoutHTTPStagesNativeFailuresAndUnsafeOutput(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result SAMLLogoutRequestResult
		err    error
		status int
	}{
		{"native denial", SAMLLogoutRequestResult{Destination: samlLogoutHTTPEndpoint, SAMLResponse: "must-not-leak"}, identity.ForbiddenError{}, 403},
		{"native failure", SAMLLogoutRequestResult{Destination: samlLogoutHTTPEndpoint, SAMLResponse: "must-not-leak"}, errors.New("owner unavailable"), 503},
		{"foreign destination", SAMLLogoutRequestResult{Destination: "https://foreign.example/logout", SAMLResponse: "YQ=="}, nil, 503},
		{"different IdP path", SAMLLogoutRequestResult{Destination: samlLogoutHTTPIDP + "/unselected", SAMLResponse: "YQ=="}, nil, 503},
		{"destination without response", SAMLLogoutRequestResult{Destination: samlLogoutHTTPEndpoint}, nil, 503},
		{"response without destination", SAMLLogoutRequestResult{SAMLResponse: "YQ=="}, nil, 503},
		{"malformed output", SAMLLogoutRequestResult{Destination: samlLogoutHTTPEndpoint, SAMLResponse: `"><script>bad()</script>`}, nil, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSAMLLogoutHTTPFixture(t)
			f.owner.request = func(context.Context, SAMLLogoutRequest) (SAMLLogoutRequestResult, error) { return tc.result, tc.err }
			w := f.serve(f.request("SAMLRequest"))
			assertSAMLLogoutHTTPDenied(t, f, w, tc.status)
			if strings.Contains(w.Body.String(), "must-not-leak") {
				t.Fatal("native error's uncommitted response escaped staging")
			}
		})
	}
	for _, target := range []string{"https://foreign.example/bye", samlLogoutHTTPOrigin + "/unselected", samlLogoutHTTPFinish + "?next=foreign", "//foreign.example", "javascript:alert(1)"} {
		t.Run("unsafe continuation "+target, func(t *testing.T) {
			f := newSAMLLogoutHTTPFixture(t)
			f.owner.response = func(context.Context, SAMLLogoutResponseRequest) (SAMLLogoutResponseResult, error) {
				return SAMLLogoutResponseResult{FinalRedirect: target}, nil
			}
			assertSAMLLogoutHTTPDenied(t, f, f.serve(f.request("SAMLResponse")), http.StatusServiceUnavailable)
		})
	}
	for _, field := range []string{"SAMLRequest", "SAMLResponse"} {
		t.Run(field+" canceled after owner", func(t *testing.T) {
			f := newSAMLLogoutHTTPFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f.owner.request = func(context.Context, SAMLLogoutRequest) (SAMLLogoutRequestResult, error) {
				cancel()
				return SAMLLogoutRequestResult{Destination: samlLogoutHTTPEndpoint, SAMLResponse: f.signedResponse}, nil
			}
			f.owner.response = func(context.Context, SAMLLogoutResponseRequest) (SAMLLogoutResponseResult, error) {
				cancel()
				return SAMLLogoutResponseResult{FinalRedirect: samlLogoutHTTPFinish}, nil
			}
			assertSAMLLogoutHTTPDenied(t, f, f.serve(f.request(field).WithContext(ctx)), http.StatusServiceUnavailable)
		})
	}
}

func TestSAMLLogoutHTTPUsesSharedProviderIPQuotaBeforeEitherOwnerBranch(t *testing.T) {
	f := newSAMLLogoutHTTPFixture(t)
	for i := range 31 {
		field := "SAMLRequest"
		if i%2 == 1 {
			field = "SAMLResponse"
		}
		w := f.serve(f.request(field))
		if i == 30 {
			assertSAMLLogoutHTTPDenied(t, f, w, http.StatusTooManyRequests)
			if w.Header().Get("Retry-After") != "20" || f.requestCalls+f.responseCalls != 30 {
				t.Fatal("shared provider-IP quota failed to stop both branches before native work")
			}
		} else if w.Code != http.StatusOK && w.Code != http.StatusSeeOther {
			t.Fatal("SLO used a credential/transaction quota instead of its provider-IP quota", i, w.Code)
		}
	}
}

func TestSAMLLogoutHTTPPreservesEarlierDeadlineAndOriginalForm(t *testing.T) {
	f := newSAMLLogoutHTTPFixture(t)
	r := f.request("SAMLRequest")
	deadline := time.Now().Add(300 * time.Millisecond)
	ctx, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	f.owner.request = func(ownerCtx context.Context, r SAMLLogoutRequest) (SAMLLogoutRequestResult, error) {
		got, ok := ownerCtx.Deadline()
		if !ok || !got.Equal(deadline) || r.SAMLRequest != f.requestWire {
			t.Fatal("transport replaced the earlier caller deadline or decoded wire more than once")
		}
		return SAMLLogoutRequestResult{}, nil
	}
	w := f.serve(r.WithContext(ctx))
	assertSAMLLogoutHTTPDenied(t, f, w, http.StatusNoContent)
}

func TestSAMLLogoutHTTPSelectionAndConfigurationFailClosed(t *testing.T) {
	f := newSAMLLogoutHTTPFixture(t)
	for _, token := range []string{`"/saml2/{provider_id}/slo"`, `"operationId":"identity.sso.saml-slo"`, `"SAMLRequest"`, `"SAMLResponse"`, `"oneOf"`} {
		if !strings.Contains(string(f.document.JSON()), token) {
			t.Fatal("selected SLO did not publish its exclusive wire contract", token)
		}
	}
	discovery, _, _ := discoveryFixture(t)
	absent, document := discoveryRouter(t, discovery, false)
	w := httptest.NewRecorder()
	r := f.request("SAMLRequest")
	r.Header.Del("Origin") // An unselected cross-origin POST is denied before dispatch.
	absent.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound || strings.Contains(string(document.JSON()), `"/saml2/{provider_id}/slo"`) {
		t.Fatal("unselected SAML logout became a route or public wire contract")
	}
	for name, mutate := range map[string]func(*SAMLLogoutConfig){
		"missing tenant":       func(c *SAMLLogoutConfig) { c.TenantID = "" },
		"missing owner":        func(c *SAMLLogoutConfig) { c.Owner = nil },
		"missing rate":         func(c *SAMLLogoutConfig) { c.Rate = nil },
		"invalid provider":     func(c *SAMLLogoutConfig) { c.ProviderID = "../foreign" },
		"unbounded duration":   func(c *SAMLLogoutConfig) { c.MaximumDuration = 0 },
		"HTTP IdP":             func(c *SAMLLogoutConfig) { c.IdentityProviderOrigin = "http://idp.example" },
		"foreign endpoint":     func(c *SAMLLogoutConfig) { c.ResponseEndpoint = "https://foreign.example/logout" },
		"HTTP endpoint":        func(c *SAMLLogoutConfig) { c.ResponseEndpoint = "http://idp.example/logout" },
		"foreign continuation": func(c *SAMLLogoutConfig) { c.FinalRedirectAllowlist = []string{"https://foreign.example/bye"} },
	} {
		t.Run(name, func(t *testing.T) {
			config := f.config
			mutate(&config)
			if _, err := NewSAMLLogoutOperation(config); err == nil {
				t.Fatal("unsafe SAML logout configuration was accepted")
			}
		})
	}
}

func TestSAMLLogoutHTTPRequestOnlySelection(t *testing.T) {
	f := newSAMLLogoutHTTPFixture(t)
	f.config.RequestOnlyOwner = f.owner
	if _, err := NewSAMLLogoutOperation(f.config); err == nil {
		t.Fatal("request-only selection accepted a second owner")
	}
	f.config.Owner = nil
	if _, err := NewSAMLLogoutOperation(f.config); err == nil {
		t.Fatal("request-only selection accepted response continuations")
	}
	f.config.FinalRedirectAllowlist = nil
	f.rebuild(t)
	document := string(f.document.JSON())
	if !strings.Contains(document, `"SAMLRequest"`) || strings.Contains(document, `"SAMLResponse"`) ||
		strings.Contains(document, `"303"`) {
		t.Fatal("request-only OpenAPI advertises response settlement")
	}
	assertSAMLLogoutHTTPDenied(t, f, f.serve(f.request("SAMLResponse")), http.StatusBadRequest)
	if f.requestCalls != 0 || f.responseCalls != 0 {
		t.Fatal("unselected response reached an owner")
	}
	w := f.serve(f.request("SAMLRequest"))
	if w.Code != http.StatusOK || f.requestCalls != 1 || f.responseCalls != 0 {
		t.Fatal("selected request did not reach the exact owner", w.Code)
	}
}

func FuzzSAMLLogoutWire(f *testing.F) {
	for _, wire := range []string{"YQ==", "YR==", "YQ==\r\n", "YWJj", "", "YQ=", "<xml>"} {
		f.Add(wire)
	}
	f.Fuzz(func(t *testing.T, wire string) {
		if len(wire) > samlLogoutMaxWire {
			if validSAMLLogoutWire(wire) {
				t.Fatal("accepted oversized wire")
			}
			return
		}
		decoded, err := base64.StdEncoding.DecodeString(wire)
		canonical := err == nil && len(decoded) != 0 && base64.StdEncoding.EncodeToString(decoded) == wire
		if validSAMLLogoutWire(wire) != canonical {
			t.Fatal("accepted wire differs from its canonical encoding")
		}
	})
}
