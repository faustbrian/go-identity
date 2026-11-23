package ssohttp

import (
	"context"
	"encoding/base64"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
)

type samlIDPHTTPProbe struct {
	prepare func(context.Context, SAMLIDPArrivalRequest) (SAMLIDPArrivalResult, error)
	source  func(context.Context, SAMLIDPConfirmationRequest) (SAMLIDPConfirmationRateContext, error)
	confirm func(context.Context, SAMLIDPConfirmationRequest) (SigninCallbackResult, error)
}

func (p *samlIDPHTTPProbe) PrepareSAMLIDP(ctx context.Context, r SAMLIDPArrivalRequest) (SAMLIDPArrivalResult, error) {
	return p.prepare(ctx, r)
}

func (p *samlIDPHTTPProbe) SAMLIDPConfirmationRateSource(ctx context.Context, r SAMLIDPConfirmationRequest) (SAMLIDPConfirmationRateContext, error) {
	return p.source(ctx, r)
}

func (p *samlIDPHTTPProbe) ConfirmSAMLIDP(ctx context.Context, r SAMLIDPConfirmationRequest) (SigninCallbackResult, error) {
	return p.confirm(ctx, r)
}

const (
	samlIDPTestOrigin   = "https://tenant.example"
	samlIDPTestIssuer   = "https://idp.example"
	samlIDPTestProvider = "-installed"
	samlIDPTestPath     = "/saml2/" + samlIDPTestProvider + "/idp-init"
	samlIDPTestFinish   = samlIDPTestOrigin + "/signed-in"
)

type samlIDPHTTPFixture struct {
	config                           SAMLIDPSigninConfig
	owner                            *samlIDPHTTPProbe
	router                           http.Handler
	pending                          identity.CommandID
	browser, synchronizer            string
	assertion                        string
	arrivals, sources, confirmations int
}

func newSAMLIDPHTTPFixture(t *testing.T) *samlIDPHTTPFixture {
	t.Helper()
	discovery, _, _ := discoveryFixture(t)
	auth, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	pending, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	f := &samlIDPHTTPFixture{pending: pending,
		browser:      base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("b", 32))),
		synchronizer: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("f", 32))),
		assertion:    base64.StdEncoding.EncodeToString([]byte("<native-validated-unsolicited-response/>"))}
	f.owner = &samlIDPHTTPProbe{}
	f.config = SAMLIDPSigninConfig{Network: discovery.Network, TenantID: testTenant, Origin: samlIDPTestOrigin,
		IdentityProviderOrigin: samlIDPTestIssuer, ProviderID: samlIDPTestProvider, SuccessCallback: samlIDPTestFinish,
		Audience: "enterprise-app", Cookie: auth, CSRFCookie: csrf, Rate: discovery.Rate, Now: discovery.Now,
		MaximumDuration: time.Second, Owner: f.owner}
	f.config.Network.TenantHosts = append(f.config.Network.TenantHosts, identityhttp.TenantHost{Host: "alias.example", TenantID: testTenant})
	f.owner.prepare = func(ctx context.Context, r SAMLIDPArrivalRequest) (SAMLIDPArrivalResult, error) {
		f.arrivals++
		if _, bounded := ctx.Deadline(); !bounded || r.TenantID != testTenant || r.ProviderID != samlIDPTestProvider ||
			r.ReceivedAssertionConsumerURL != samlIDPTestOrigin+samlIDPTestPath || r.SAMLResponse != f.assertion {
			t.Fatal("arrival lost bounded exact provider, destination or original response custody")
		}
		return SAMLIDPArrivalResult{PendingID: f.pending, BrowserCookie: authentication.NewBearerCredential(f.browser),
			Synchronizer: authentication.NewBearerCredential(f.synchronizer), ExpiresAt: discovery.Now().Add(3 * time.Minute)}, nil
	}
	validConfirmation := func(ctx context.Context, r SAMLIDPConfirmationRequest) bool {
		_, bounded := ctx.Deadline()
		return bounded && r.TenantID == testTenant && r.ProviderID == samlIDPTestProvider && r.PendingID == f.pending &&
			r.Origin == samlIDPTestOrigin && r.Browser.Token() == f.browser && r.Form.Token() == f.synchronizer
	}
	f.owner.source = func(ctx context.Context, r SAMLIDPConfirmationRequest) (SAMLIDPConfirmationRateContext, error) {
		f.sources++
		if !validConfirmation(ctx, r) {
			return SAMLIDPConfirmationRateContext{}, identity.ForbiddenError{}
		}
		return SAMLIDPConfirmationRateContext{ProviderID: samlIDPTestProvider, PendingID: f.pending, Lifetime: 3 * time.Minute}, nil
	}
	f.owner.confirm = func(ctx context.Context, r SAMLIDPConfirmationRequest) (SigninCallbackResult, error) {
		f.confirmations++
		if f.sources == 0 || !validConfirmation(ctx, r) {
			t.Fatal("confirmation preceded authenticated rate attribution or changed original credential roles")
		}
		command, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		spOperation := identity.FeatureOperation{Owner: "sso/saml", OperationID: "identity.sso.saml-acs", SchemaID: "sso-enterprise-saml-acs-v1",
			SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectAnonymousFlow, RecordRequirement: identity.FeatureRecordRequired}
		flow, err := identity.NewPreAuthTransactionID()
		if err != nil {
			t.Fatal(err)
		}
		result := enterpriseIssueFixtureForOperation(t, SigninCallbackConfig{Browser: SigninBrowserConfig{TenantID: testTenant, Now: discovery.Now},
			Audience: f.config.Audience, Cookie: auth, CSRFCookie: csrf, CallbackAllowlist: []string{samlIDPTestFinish}}, flow, command, spOperation, "sso-saml")
		result.Completion.Binding.AnonymousFlowID = ""
		result.Completion.Binding.UserID = "member"
		result.Completion.Binding.RecordID = string(f.pending)
		result.Completion.Binding.OperationID = "identity.sso.saml-idp-init"
		result.Completion.Binding.SchemaID = "sso-enterprise-saml-idp-init-v1"
		result.RedirectURI = "" // native confirmation cannot select the transport redirect
		result.Completion.Feature.Operation = identity.FeatureOperation{Owner: "sso/saml", OperationID: "identity.sso.saml-idp-init",
			SchemaID: "sso-enterprise-saml-idp-init-v1", SchemaVersion: 1, SubjectRequirement: identity.FeatureSubjectUser, RecordRequirement: identity.FeatureRecordRequired}
		if err := result.Completion.Validate(); err != nil {
			t.Fatal("invalid native confirmation delivery fixture", err)
		}
		return result, nil
	}
	op, err := NewSAMLIDPInitiatedOperation(f.config)
	if err != nil {
		t.Fatal("select opt-in IdP-initiated operation", err)
	}
	f.router, _, err = identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: time.Second,
		CORS: []identityhttp.CORSRoutePolicy{f.config.NavigationPolicy()}, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}},
		[]identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal("compose IdP-initiated operation through canonical router", err)
	}
	return f
}

func (f *samlIDPHTTPFixture) request(origin, payload string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, samlIDPTestOrigin+samlIDPTestPath, strings.NewReader(payload))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "192.0.2.17:32000"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return r
}

func (f *samlIDPHTTPFixture) serve(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func (f *samlIDPHTTPFixture) arrivalForm() string {
	return url.Values{"SAMLResponse": {f.assertion}}.Encode()
}

func (f *samlIDPHTTPFixture) confirmationForm() string {
	return url.Values{"pending": {string(f.pending)}, "confirmation": {f.synchronizer}}.Encode()
}

func (f *samlIDPHTTPFixture) browserCookie() *http.Cookie {
	return &http.Cookie{Name: "__Secure-identity_frontchannel", Value: f.browser}
}

func assertSAMLIDPHTTPDenied(t *testing.T, f *samlIDPHTTPFixture, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status || w.Header().Get("Location") != "" || len(w.Header().Values("Set-Cookie")) != 0 ||
		w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" ||
		strings.Contains(w.Body.String(), f.assertion) || strings.Contains(w.Body.String(), f.browser) || strings.Contains(w.Body.String(), f.synchronizer) {
		t.Fatalf("denial changed browser custody or status: got %d, want %d", w.Code, status)
	}
}

func TestSAMLIDPHTTPArrivalRequiresSameBrowserConfirmationBeforeSessionDelivery(t *testing.T) {
	f := newSAMLIDPHTTPFixture(t)
	arrival := f.serve(f.request(samlIDPTestIssuer, f.arrivalForm()))
	cookies := arrival.Result().Cookies()
	if arrival.Code != http.StatusOK || arrival.Header().Get("Location") != "" || len(cookies) != 1 ||
		!strings.HasPrefix(arrival.Header().Get("Content-Type"), "text/html") || arrival.Header().Get("Cache-Control") != "no-store" ||
		arrival.Header().Get("Referrer-Policy") != "no-referrer" || arrival.Header().Get("Access-Control-Allow-Origin") != "" ||
		arrival.Header().Get("Access-Control-Allow-Credentials") != "" || f.arrivals != 1 || f.sources != 0 || f.confirmations != 0 {
		t.Fatal("arrival did not stop at a private confirmation document", arrival.Code)
	}
	cookie := cookies[0]
	if cookie.Name != "__Secure-identity_frontchannel" || cookie.Value != f.browser || cookie.Domain != "" || cookie.Path != samlIDPTestPath ||
		!cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || cookie.MaxAge != 180 || !cookie.Expires.Equal(f.config.Now().Add(3*time.Minute)) {
		t.Fatal("arrival did not issue only original host-only, exact-path confirmation custody")
	}
	body := arrival.Body.String()
	if strings.Contains(body, f.assertion) || strings.Contains(body, f.browser) || strings.Contains(body, "SAMLResponse") ||
		strings.Contains(body, "RelayState") || strings.Contains(strings.ToLower(body), "<script") || strings.Contains(strings.ToLower(body), "http-equiv") {
		t.Fatal("confirmation document leaked assertion/browser custody or automatically navigated")
	}
	inputs := regexp.MustCompile(`<input\b[^>]*>`).FindAllString(body, -1)
	attributes := regexp.MustCompile(`\s([a-z]+)="([^"]*)"`)
	forms := regexp.MustCompile(`<form\b[^>]*>`).FindAllString(body, -1)
	if len(forms) != 1 {
		t.Fatal("confirmation did not render exactly one explicit submission form")
	}
	formAttributes := make(map[string]string)
	for _, match := range attributes.FindAllStringSubmatch(forms[0], -1) {
		formAttributes[match[1]] = html.UnescapeString(match[2])
	}
	if strings.ToLower(formAttributes["method"]) != "post" ||
		(formAttributes["action"] != samlIDPTestPath && formAttributes["action"] != samlIDPTestOrigin+samlIDPTestPath) {
		t.Fatal("confirmation form did not post back to the exact selected SP route")
	}
	hidden := make(url.Values)
	for _, input := range inputs {
		attrs := make(map[string]string)
		for _, match := range attributes.FindAllStringSubmatch(input, -1) {
			attrs[match[1]] = html.UnescapeString(match[2])
		}
		if attrs["type"] == "hidden" {
			hidden.Add(attrs["name"], attrs["value"])
		}
	}
	if len(hidden) != 2 || len(hidden["pending"]) != 1 || hidden.Get("pending") != string(f.pending) ||
		len(hidden["confirmation"]) != 1 || hidden.Get("confirmation") != f.synchronizer || !strings.Contains(body, "<form") {
		t.Fatal("confirmation document did not contain only exact native pending ID and independent form credential")
	}
	// For a same-origin navigation POST, Fetch sends a null Origin under
	// no-referrer. The document's referrer metadata supersedes the HTTP default.
	policy := arrival.Header().Get("Referrer-Policy")
	for _, meta := range regexp.MustCompile(`<meta\b[^>]*>`).FindAllString(body, -1) {
		attrs := make(map[string]string)
		for _, match := range attributes.FindAllStringSubmatch(meta, -1) {
			attrs[match[1]] = html.UnescapeString(match[2])
		}
		if attrs["name"] == "referrer" {
			policy = attrs["content"]
		}
	}
	var formOrigin string
	switch policy {
	case "no-referrer":
		formOrigin = "null"
	case "same-origin":
		formOrigin = samlIDPTestOrigin
	default:
		t.Fatal("unexpected confirmation document referrer policy")
	}
	confirmed := f.serve(f.request(formOrigin, hidden.Encode(), cookie))
	issued := confirmed.Result().Cookies()
	if confirmed.Code != http.StatusSeeOther || confirmed.Header().Get("Location") != samlIDPTestFinish || len(issued) != 3 ||
		issued[0].Name != "__Host-identity_session" || issued[0].Value == "" || issued[0].Value == f.browser || issued[0].Value == f.synchronizer ||
		issued[1].Name != "__Host-identity_csrf" || issued[1].Value == "" || issued[2].Name != cookie.Name || issued[2].Path != samlIDPTestPath || issued[2].MaxAge >= 0 ||
		confirmed.Header().Get("Access-Control-Allow-Origin") != "" || confirmed.Header().Get("Access-Control-Allow-Credentials") != "" ||
		f.arrivals != 1 || f.sources != 1 || f.confirmations != 1 {
		t.Fatalf("same-browser confirmation with effective policy %q did not deliver a fresh session/CSRF and clear pending custody: %d", policy, confirmed.Code)
	}
}

func TestSAMLIDPHTTPRejectsAmbiguousAndCrossBranchInputsBeforeNativeWork(t *testing.T) {
	f := newSAMLIDPHTTPFixture(t)
	for _, tc := range []struct {
		name, origin, payload string
		cookies               []*http.Cookie
		status                int
		mutate                func(*http.Request)
	}{
		{name: "foreign arrival", origin: "https://foreign.example", payload: f.arrivalForm(), status: 403},
		{name: "missing origin", payload: f.arrivalForm(), status: 403},
		{name: "opaque origin", origin: "null", payload: f.arrivalForm(), status: 403},
		{name: "duplicate origin", origin: samlIDPTestIssuer, payload: f.arrivalForm(), status: 400, mutate: func(r *http.Request) { r.Header.Add("Origin", samlIDPTestIssuer) }},
		{name: "IdP confirmation", origin: samlIDPTestIssuer, payload: f.confirmationForm(), cookies: []*http.Cookie{f.browserCookie()}, status: 403},
		{name: "SP assertion", origin: samlIDPTestOrigin, payload: f.arrivalForm(), status: 403},
		{name: "relay unselected", origin: samlIDPTestIssuer, payload: f.arrivalForm() + "&RelayState=unselected", status: 400},
		{name: "duplicate response", origin: samlIDPTestIssuer, payload: f.arrivalForm() + "&" + f.arrivalForm(), status: 400},
		{name: "arrival confirmation mix", origin: samlIDPTestIssuer, payload: f.arrivalForm() + "&" + f.confirmationForm(), status: 400},
		{name: "confirmation assertion mix", origin: samlIDPTestOrigin, payload: f.confirmationForm() + "&" + f.arrivalForm(), cookies: []*http.Cookie{f.browserCookie()}, status: 400},
		{name: "duplicate pending", origin: samlIDPTestOrigin, payload: f.confirmationForm() + "&pending=" + string(f.pending), cookies: []*http.Cookie{f.browserCookie()}, status: 400},
		{name: "duplicate confirmation", origin: samlIDPTestOrigin, payload: f.confirmationForm() + "&confirmation=" + f.synchronizer, cookies: []*http.Cookie{f.browserCookie()}, status: 400},
		{name: "missing browser", origin: samlIDPTestOrigin, payload: f.confirmationForm(), status: 403},
		{name: "duplicate browser", origin: samlIDPTestOrigin, payload: f.confirmationForm(), cookies: []*http.Cookie{f.browserCookie(), f.browserCookie()}, status: 403},
		{name: "query cannot select phase", origin: samlIDPTestIssuer, payload: f.arrivalForm(), status: 400, mutate: func(r *http.Request) {
			r.URL.RawQuery = "pending=" + string(f.pending)
			r.RequestURI = r.URL.RequestURI()
		}},
		{name: "same tenant alias", origin: samlIDPTestIssuer, payload: f.arrivalForm(), status: 403, mutate: func(r *http.Request) { r.Host = "alias.example" }},
		{name: "cross tenant", origin: samlIDPTestIssuer, payload: f.arrivalForm(), status: 403, mutate: func(r *http.Request) { r.Host = "other.example" }},
		{name: "preflight", origin: samlIDPTestIssuer, status: 403, mutate: func(r *http.Request) {
			r.Method = http.MethodOptions
			r.Header.Set("Access-Control-Request-Method", http.MethodPost)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := f.request(tc.origin, tc.payload, tc.cookies...)
			if tc.mutate != nil {
				tc.mutate(r)
			}
			assertSAMLIDPHTTPDenied(t, f, f.serve(r), tc.status)
			if f.arrivals != 0 || f.sources != 0 || f.confirmations != 0 {
				t.Fatal("untrusted phase, form, origin or cookie reached native work")
			}
		})
	}
}

func TestSAMLIDPHTTPNativeDenialNeverEmitsCookiesOrRedirect(t *testing.T) {
	t.Run("arrival rejected by native owner", func(t *testing.T) {
		f := newSAMLIDPHTTPFixture(t)
		f.owner.prepare = func(context.Context, SAMLIDPArrivalRequest) (SAMLIDPArrivalResult, error) {
			return SAMLIDPArrivalResult{}, identity.ForbiddenError{}
		}
		assertSAMLIDPHTTPDenied(t, f, f.serve(f.request(samlIDPTestIssuer, f.arrivalForm())), 403)
	})
	for _, tc := range []struct {
		name   string
		change func(*samlIDPHTTPFixture, *http.Request)
	}{
		{name: "swapped credential roles", change: func(f *samlIDPHTTPFixture, r *http.Request) {
			payload := url.Values{"pending": {string(f.pending)}, "confirmation": {f.browser}}.Encode()
			*r = *f.request(samlIDPTestOrigin, payload, &http.Cookie{Name: f.browserCookie().Name, Value: f.synchronizer})
		}},
		{name: "foreign pending", change: func(f *samlIDPHTTPFixture, r *http.Request) {
			other, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			*r = *f.request(samlIDPTestOrigin, url.Values{"pending": {string(other)}, "confirmation": {f.synchronizer}}.Encode(), f.browserCookie())
		}},
		{name: "native locator denial", change: func(f *samlIDPHTTPFixture, _ *http.Request) {
			f.owner.source = func(context.Context, SAMLIDPConfirmationRequest) (SAMLIDPConfirmationRateContext, error) {
				return SAMLIDPConfirmationRateContext{}, identity.ForbiddenError{}
			}
		}},
		{name: "foreign native attribution", change: func(f *samlIDPHTTPFixture, _ *http.Request) {
			f.owner.source = func(context.Context, SAMLIDPConfirmationRequest) (SAMLIDPConfirmationRateContext, error) {
				return SAMLIDPConfirmationRateContext{ProviderID: "other", PendingID: f.pending, Lifetime: time.Minute}, nil
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSAMLIDPHTTPFixture(t)
			r := f.request(samlIDPTestOrigin, f.confirmationForm(), f.browserCookie())
			tc.change(f, r)
			assertSAMLIDPHTTPDenied(t, f, f.serve(r), 403)
			if f.confirmations != 0 {
				t.Fatal("unauthenticated native attribution reached protected confirmation")
			}
		})
	}
	t.Run("protected confirmation denial", func(t *testing.T) {
		f := newSAMLIDPHTTPFixture(t)
		f.owner.confirm = func(context.Context, SAMLIDPConfirmationRequest) (SigninCallbackResult, error) {
			f.confirmations++
			return SigninCallbackResult{}, identity.ForbiddenError{}
		}
		assertSAMLIDPHTTPDenied(t, f, f.serve(f.request(samlIDPTestOrigin, f.confirmationForm(), f.browserCookie())), 403)
		if f.sources != 1 || f.confirmations != 1 {
			t.Fatal("confirmation did not follow authenticated native attribution")
		}
	})
}
