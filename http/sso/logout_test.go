package ssohttp

import (
	"context"
	"crypto/tls"
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
	"github.com/faustbrian/go-sso/oidc"
)

const (
	logoutStartPath    = "/sso/oidc/Enterprise_OIDC-01/logout"
	logoutCallbackPath = logoutStartPath + "/callback"
	logoutSessionWire  = "synthetic-logout-session"
	logoutStateWire    = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE"
)

type providerLogoutProbe struct {
	t                          testing.TB
	starts, attributions, ends int
	start                      ProviderLogoutStartRequest
	attribution, complete      ProviderLogoutCompleteRequest
	rate                       ProviderLogoutRateContext
	startResult                oidc.LogoutStartResult
	completeResult             oidc.LogoutCompleteResult
	startErr, completeErr      error
}

func (p *providerLogoutProbe) StartSSOOIDCLogout(ctx context.Context, request ProviderLogoutStartRequest) (oidc.LogoutStartResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("logout start reached native authority without a deadline")
	}
	p.starts++
	p.start = request
	return p.startResult, p.startErr
}

func (p *providerLogoutProbe) SSOOIDCLogoutRateSource(ctx context.Context, request ProviderLogoutCompleteRequest) (ProviderLogoutRateContext, error) {
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("logout attribution reached native authority without a deadline")
	}
	p.attributions++
	p.attribution = request
	return p.rate, nil
}

func (p *providerLogoutProbe) CompleteSSOOIDCLogout(ctx context.Context, request ProviderLogoutCompleteRequest) (oidc.LogoutCompleteResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("logout callback reached native authority without a deadline")
	}
	p.ends++
	p.complete = request
	return p.completeResult, p.completeErr
}

func providerLogoutFixture(t testing.TB) (ProviderLogoutConfig, *providerLogoutProbe) {
	t.Helper()
	discovery, _, _ := discoveryFixture(t)
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-logout_session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-logout_csrf", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	probe := &providerLogoutProbe{t: t, rate: ProviderLogoutRateContext{ProviderID: "Enterprise_OIDC-01", TransactionID: "AQEBAQEBAQEBAQEBAQEBAQ", Lifetime: time.Minute}}
	return ProviderLogoutConfig{
		Network: discovery.Network, TenantID: testTenant, Origin: "https://tenant.example", Rate: discovery.Rate,
		MaximumDuration: time.Second, Cookie: cookie, CSRFCookie: csrf,
		Providers:              []ProviderLogoutRoute{{ProviderID: "Enterprise_OIDC-01", EndSessionEndpoint: "https://provider.example/end-session"}},
		FinalRedirectAllowlist: []string{"https://tenant.example/bye"}, Owner: probe,
	}, probe
}

func providerLogoutRouter(t testing.TB, config ProviderLogoutConfig, selected bool) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	services := identityhttp.FeatureServices{}
	if selected {
		feature, err := NewProviderLogoutFeature(config)
		if err != nil {
			t.Fatal(err)
		}
		services.Features = []identityhttp.Feature{feature}
	}
	operations, err := identityhttp.NewOperationDescriptors(services)
	if err != nil {
		t.Fatal(err)
	}
	router, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{
		Network: config.Network, HandlerTimeout: time.Second,
		Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"},
	}, operations, nil)
	if err != nil {
		t.Fatal(err)
	}
	return router, document
}

func providerLogoutRequest(method, path, body string) *http.Request {
	target := "https://tenant.example" + path
	r := httptest.NewRequest(method, target, nil)
	if body != "" {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "192.0.2.17:32000"
	r.TLS = &tls.ConnectionState{}
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://tenant.example")
		r.Header.Set("Idempotency-Key", "original-logout-key")
		r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43))
		r.AddCookie(&http.Cookie{Name: "__Host-logout_session", Value: logoutSessionWire})
	}
	return r
}

func providerLogoutReceipt(t testing.TB, operation string, outcome identity.CommitOutcome) oidc.Completion {
	t.Helper()
	schema := "sso-enterprise-oidc-logout-v1"
	if operation == "identity.sso.oidc-logout-complete" {
		schema = "sso-enterprise-oidc-logout-complete-v1"
	}
	descriptor := identity.FeatureOperation{Owner: "sso/oidc", OperationID: operation, SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	receipt := identity.CommandResult{
		Binding: identity.CommandBinding{
			CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: testTenant, UserID: "logout-user", ActorID: "logout-user",
			ActorKind: authorization.SubjectUser, OperationID: operation, SchemaID: schema, SchemaVersion: 1,
			PolicyID: "logout-policy", PolicyVersion: 1, CorrelationID: "logout-correlation", RecordID: "logout-session",
		}, Outcome: outcome, Feature: &identity.FeatureReceipt{Operation: descriptor},
	}
	if outcome == identity.CommitOutcomeCommitted {
		receipt.AuditEventID = "logout-audit"
		receipt.Feature.BeforeVersion, receipt.Feature.AfterVersion = 1, 2
	}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func requireLogoutCookieDeletion(t testing.TB, response *httptest.ResponseRecorder) {
	t.Helper()
	cookies := response.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatal("committed start must delete exactly its session and CSRF cookies")
	}
	seen := make(map[string]bool)
	for _, cookie := range cookies {
		if cookie.Name != "__Host-logout_session" && cookie.Name != "__Host-logout_csrf" || seen[cookie.Name] {
			t.Fatal("logout deleted an unrelated or duplicate cookie")
		}
		if cookie.Value != "" || cookie.MaxAge != -1 || !cookie.Expires.Equal(time.Unix(1, 0)) || cookie.Path != "/" || cookie.Domain != "" {
			t.Fatal("logout changed the configured deletion scope or retained browser custody")
		}
		if !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.HttpOnly != (cookie.Name == "__Host-logout_session") {
			t.Fatal("logout weakened the configured cookie security attributes")
		}
		seen[cookie.Name] = true
	}
}

func TestProviderLogoutRoutesAndOpenAPIRequireExplicitSelection(t *testing.T) {
	config, probe := providerLogoutFixture(t)
	off, absent := providerLogoutRouter(t, config, false)
	for _, request := range []*http.Request{
		providerLogoutRequest(http.MethodPost, logoutStartPath, `{"finalRedirect":"https://tenant.example/bye"}`),
		providerLogoutRequest(http.MethodGet, logoutCallbackPath+"?state="+logoutStateWire, ""),
	} {
		w := httptest.NewRecorder()
		off.ServeHTTP(w, request)
		if w.Code != http.StatusNotFound || probe.starts != 0 || probe.attributions != 0 || probe.ends != 0 {
			t.Fatal("unselected provider logout reached a route or native authority", w.Code)
		}
	}
	if strings.Contains(string(absent.JSON()), "identity.sso.oidc-logout") {
		t.Fatal("unselected provider logout appeared in OpenAPI")
	}
	on, selected := providerLogoutRouter(t, config, true)
	for _, required := range []string{`"/sso/oidc/{provider_id}/logout"`, `"/sso/oidc/{provider_id}/logout/callback"`, `"operationId":"identity.sso.oidc-logout"`, `"operationId":"identity.sso.oidc-logout-complete"`, `"finalRedirect"`, `"X-CSRF-Token"`, `"Idempotency-Key"`} {
		if !strings.Contains(string(selected.JSON()), required) {
			t.Fatal("selected logout did not publish its canonical contract", required)
		}
	}
	w := httptest.NewRecorder()
	on.ServeHTTP(w, providerLogoutRequest(http.MethodPost, "/sso/oidc/unconfigured/logout", `{"finalRedirect":"https://tenant.example/bye"}`))
	if w.Code != http.StatusNotFound || probe.starts != 0 {
		t.Fatal("an unselected provider path reached native logout", w.Code)
	}
}

func TestProviderLogoutStartPreservesNativeInputAndCommittedDelivery(t *testing.T) {
	for _, tc := range []struct {
		name     string
		outcome  oidc.OIDCLogoutOutcome
		local    identity.CommitOutcome
		redirect string
		status   int
		body     string
		delete   bool
	}{
		{"redirect", oidc.OIDCLogoutRedirect, identity.CommitOutcomeCommitted, "https://provider.example/end-session?client_id=logout-test-client&post_logout_redirect_uri=https%3A%2F%2Ftenant.example%2Fsso%2Foidc%2FEnterprise_OIDC-01%2Flogout%2Fcallback&state=" + logoutStateWire, 303, "", true},
		{"local only", oidc.OIDCLogoutLocalOnly, identity.CommitOutcomeCommitted, "", 200, `{"outcome":"local-only"}`, true},
		{"unknown local command", oidc.OIDCLogoutUnknownReconciliation, identity.CommitOutcomeUnknown, "", 503, "", false},
		{"unknown provider after local commit", oidc.OIDCLogoutUnknownReconciliation, identity.CommitOutcomeCommitted, "", 503, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, probe := providerLogoutFixture(t)
			var redirect url.URL
			if tc.redirect != "" {
				parsed, err := url.Parse(tc.redirect)
				if err != nil {
					t.Fatal(err)
				}
				redirect = *parsed
			}
			var err error
			probe.startResult, err = oidc.NewLogoutStartResult(tc.outcome, redirect, providerLogoutReceipt(t, "identity.sso.oidc-logout", tc.local))
			if err != nil {
				t.Fatal(err)
			}
			router, _ := providerLogoutRouter(t, config, true)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, providerLogoutRequest(http.MethodPost, logoutStartPath, `{"finalRedirect":"https://tenant.example/bye"}`))
			csrf, err := probe.start.CSRF.Reveal()
			if probe.starts != 1 || probe.start.TenantID != testTenant || probe.start.ProviderID != "Enterprise_OIDC-01" || probe.start.Origin != "https://tenant.example" || probe.start.FinalRedirect != "https://tenant.example/bye" || probe.start.Session.Token() != logoutSessionWire || err != nil || csrf != strings.Repeat("A", 43) {
				t.Fatal("start did not preserve the exact tenant, selected provider and original browser input")
			}
			key, err := identity.NewIdempotencyKey([]byte("original-logout-key"))
			if err != nil {
				t.Fatal(err)
			}
			want, err := key.Digest([32]byte{9})
			if err != nil {
				t.Fatal(err)
			}
			got, err := probe.start.IdempotencyKey.Digest([32]byte{9})
			if err != nil || got != want {
				t.Fatal("start replaced the original idempotency key")
			}
			if w.Code != tc.status || w.Header().Get("Location") != tc.redirect || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("logout start projected the wrong disposition or response policy", w.Code)
			}
			if tc.body != "" && strings.TrimSpace(w.Body.String()) != tc.body || tc.redirect != "" && w.Body.Len() != 0 {
				t.Fatal("logout start disclosed more than its selected wire disposition")
			}
			if tc.delete {
				requireLogoutCookieDeletion(t, w)
			} else if w.Header().Get("Set-Cookie") != "" {
				t.Fatal("unresolved logout deleted browser custody")
			}
		})
	}
}

func TestProviderLogoutStartRejectsAlternateAuthorityBeforeNativeCall(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"foreign Origin":   func(r *http.Request) { r.Header.Set("Origin", "https://other.example") },
		"missing Origin":   func(r *http.Request) { r.Header.Del("Origin") },
		"missing CSRF":     func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"missing key":      func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"missing session":  func(r *http.Request) { r.Header.Del("Cookie") },
		"alternate bearer": func(r *http.Request) { r.Header.Set("Authorization", "Bearer synthetic-other-session") },
		"other tenant":     func(r *http.Request) { r.Host = "other.example" },
	} {
		t.Run(name, func(t *testing.T) {
			config, probe := providerLogoutFixture(t)
			router, _ := providerLogoutRouter(t, config, true)
			r := providerLogoutRequest(http.MethodPost, logoutStartPath, `{"finalRedirect":"https://tenant.example/bye"}`)
			mutate(r)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code < 400 || probe.starts != 0 || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
				t.Fatal("invalid browser authority reached native logout or disclosed delivery", w.Code)
			}
		})
	}
	t.Run("foreign redirect", func(t *testing.T) {
		config, probe := providerLogoutFixture(t)
		router, _ := providerLogoutRouter(t, config, true)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, providerLogoutRequest(http.MethodPost, logoutStartPath, `{"finalRedirect":"https://foreign.example/bye"}`))
		if w.Code < 400 || probe.starts != 0 || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("an unallowlisted target reached native logout or disclosed delivery", w.Code)
		}
	})
	for _, body := range []string{`{"finalRedirect":"https://tenant.example/bye","providerID":"other"}`, `{"finalRedirect":"https://tenant.example/bye","session":"other"}`, `{"finalRedirect":"https://tenant.example/bye","finalRedirect":"https://tenant.example/bye"}`} {
		config, probe := providerLogoutFixture(t)
		router, _ := providerLogoutRouter(t, config, true)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, providerLogoutRequest(http.MethodPost, logoutStartPath, body))
		if w.Code != http.StatusBadRequest || probe.starts != 0 {
			t.Fatal("logout accepted an open or ambiguous JSON authority channel", w.Code)
		}
	}
}

func TestProviderLogoutCallbackUsesTrustedURIAndOriginalRateAttributionWithoutCookies(t *testing.T) {
	for _, tc := range []struct {
		outcome  oidc.OIDCLogoutOutcome
		wire     string
		redirect string
		status   int
	}{
		{oidc.OIDCLogoutRedirect, "redirect", "https://tenant.example/bye", http.StatusSeeOther},
		{oidc.OIDCLogoutLocalOnly, "local-only", "", http.StatusOK},
		{oidc.OIDCLogoutProviderComplete, "provider-complete", "", http.StatusOK},
		{oidc.OIDCLogoutProviderError, "provider-error", "", http.StatusOK},
		{oidc.OIDCLogoutTimeout, "timeout", "", http.StatusOK},
	} {
		t.Run(tc.wire, func(t *testing.T) {
			config, probe := providerLogoutFixture(t)
			config.Network.TrustedProxyCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
			var err error
			var redirect url.URL
			if tc.redirect != "" {
				parsed, err := url.Parse(tc.redirect)
				if err != nil {
					t.Fatal(err)
				}
				redirect = *parsed
			}
			probe.completeResult, err = oidc.NewLogoutCompleteResult(tc.outcome, redirect, providerLogoutReceipt(t, "identity.sso.oidc-logout-complete", identity.CommitOutcomeCommitted))
			if err != nil {
				t.Fatal(err)
			}
			router, _ := providerLogoutRouter(t, config, true)
			query := "state=" + logoutStateWire
			if tc.outcome == oidc.OIDCLogoutProviderError {
				query += "&error=access_denied&error_description=original%20description"
			}
			r := providerLogoutRequest(http.MethodGet, logoutCallbackPath+"?"+query, "")
			r.RemoteAddr, r.Host, r.TLS = "10.0.0.4:32000", "edge.example", nil
			r.Header.Set("Forwarded", "for=192.0.2.17;host=tenant.example;proto=https")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			want := ProviderLogoutCompleteRequest{TenantID: testTenant, ProviderID: "Enterprise_OIDC-01", CallbackURI: "https://tenant.example" + logoutCallbackPath, RawQuery: query}
			if probe.attributions != 1 || probe.ends != 1 || probe.attribution != want || probe.complete != want {
				t.Fatal("logout callback changed raw provider input or used inbound authority instead of the trusted route")
			}
			if w.Code != tc.status || w.Header().Get("Location") != tc.redirect || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("callback did not return exactly its closed outcome without browser effects", w.Code)
			}
			if tc.redirect == "" && strings.TrimSpace(w.Body.String()) != `{"outcome":"`+tc.wire+`"}` || tc.redirect != "" && w.Body.Len() != 0 {
				t.Fatal("callback disclosed data outside its selected disposition")
			}
		})
	}
}

func TestProviderLogoutCallbackWithholdsUnknownAndMismatchedAttribution(t *testing.T) {
	config, probe := providerLogoutFixture(t)
	var err error
	probe.completeResult, err = oidc.NewLogoutCompleteResult(oidc.OIDCLogoutUnknownReconciliation, url.URL{}, providerLogoutReceipt(t, "identity.sso.oidc-logout-complete", identity.CommitOutcomeUnknown))
	if err != nil {
		t.Fatal(err)
	}
	router, _ := providerLogoutRouter(t, config, true)
	query := "state=" + logoutStateWire
	serve := func(query string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		router.ServeHTTP(w, providerLogoutRequest(http.MethodGet, logoutCallbackPath+"?"+query, ""))
		return w
	}
	w := serve(query)
	if w.Code != http.StatusServiceUnavailable || probe.attributions != 1 || probe.ends != 1 || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("unknown callback claimed completion or changed browser custody", w.Code)
	}
	probe.rate.ProviderID = "other-provider"
	w = serve(query)
	if w.Code != http.StatusForbidden || probe.attributions != 2 || probe.ends != 1 || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("foreign native rate attribution selected a different provider", w.Code)
	}
	for _, invalid := range []string{query + "&state=duplicate", "state=%ZZ", "state=" + strings.Repeat("A", 4097)} {
		before := probe.attributions
		w = serve(invalid)
		if w.Code != http.StatusBadRequest || probe.attributions != before || probe.ends != 1 {
			t.Fatal("malformed provider input reached native state attribution", w.Code)
		}
	}
	probe.rate.ProviderID = "Enterprise_OIDC-01"
	probe.completeErr = sso.ErrForbidden
	w = serve(query)
	if w.Code != http.StatusForbidden || probe.ends != 2 || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("native callback refusal disclosed a provider result", w.Code)
	}
}

func TestProviderLogoutCallbackQuotaUsesOriginalTransactionAcrossIPChanges(t *testing.T) {
	config, probe := providerLogoutFixture(t)
	var err error
	probe.completeResult, err = oidc.NewLogoutCompleteResult(oidc.OIDCLogoutProviderComplete, url.URL{}, providerLogoutReceipt(t, "identity.sso.oidc-logout-complete", identity.CommitOutcomeCommitted))
	if err != nil {
		t.Fatal(err)
	}
	router, _ := providerLogoutRouter(t, config, true)
	for attempt := range 6 {
		r := providerLogoutRequest(http.MethodGet, logoutCallbackPath+"?state="+logoutStateWire, "")
		if attempt == 5 {
			r.RemoteAddr = "192.0.2.18:32000"
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if attempt < 5 && w.Code != http.StatusOK {
			t.Fatal("original provider return spent a different budget", w.Code)
		}
		if attempt == 5 && (w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || w.Header().Get("Location") != "" || w.Header().Get("Set-Cookie") != "") {
			t.Fatal("callback exceeded its five-attempt native transaction budget", w.Code)
		}
	}
	if probe.attributions != 6 || probe.ends != 5 {
		t.Fatal("a quota-denied callback reached native settlement")
	}
}
