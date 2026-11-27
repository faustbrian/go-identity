package oauthhttp_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth"
	oauthproxy "github.com/faustbrian/go-identity/oauth/proxy"
	"github.com/faustbrian/go-identity/session"
)

func proxyPreviewFixture(t *testing.T) (oauthhttp.ProxyPreviewConfig, oauthhttp.Config, *http.Request, session.BrowserDevice) {
	t.Helper()
	base, _, _, _, original, device := sharedCallbackFixture(t, "identity.oauth.signin-start")
	network, err := identityhttp.NewNetworkResolver(base.Network)
	if err != nil {
		t.Fatal(err)
	}
	c := oauthhttp.ProxyPreviewConfig{Endpoint: "https://app.example/complete", TenantID: "tenant", ProviderID: string(base.Provider.ID), Audience: base.Signin.Audience, Network: network, FlowCookie: base.Signin.FlowCookie, Cookie: base.Cookie, Device: base.Signin.Device, CSRFCookie: base.Signin.CSRFCookie, Now: base.Now, MaximumDuration: time.Second}
	c.Complete = func(context.Context, identity.PreAuthTransactionID, oauthproxy.PreviewCompletionRequest, string, string) (oauth.SigninCallbackResult, error) {
		return oauth.SigninCallbackResult{}, oauthproxy.CompletionDenied
	}
	r := httptest.NewRequest(http.MethodPost, c.Endpoint, strings.NewReader(`{"flow":"AQEBAQEBAQEBAQEBAQEBAQ","envelope":"AQID"}`))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = original.RemoteAddr
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://app.example")
	for _, cookie := range original.Cookies() {
		r.AddCookie(cookie)
	}
	return c, base, r, device
}

func serveProxyPreview(t *testing.T, c oauthhttp.ProxyPreviewConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := oauthhttp.NewProxyPreviewHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	// A selected completion must not inherit unrelated delivery authority.
	w.Header().Set("Set-Cookie", "private native detail")
	w.Header().Set("Location", "https://other.example/private")
	w.Header().Set("Authorization", "Bearer private native detail")
	w.Header().Set("X-CSRF-Token", "private native detail")
	h.ServeHTTP(w, r)
	return w
}

func TestProxyPreviewBrowserHandlerComposesOnlyExactLandingAndPost(t *testing.T) {
	c, _, original, _ := proxyPreviewFixture(t)
	handler, err := oauthhttp.NewProxyPreviewBrowserHandler(c, "https://app.example/account")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, endpoint string
		want             int
	}{
		{http.MethodGet, c.Endpoint, http.StatusOK},
		{http.MethodHead, c.Endpoint, http.StatusMethodNotAllowed},
		{http.MethodOptions, c.Endpoint, http.StatusMethodNotAllowed},
		{http.MethodGet, c.Endpoint + "/", http.StatusNotFound},
	} {
		r := httptest.NewRequest(tc.method, tc.endpoint, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.want || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Location") != "" {
			t.Fatalf("%s unexpectedly delivered state or returned %d, want %d", tc.method, w.Code, tc.want)
		}
		if tc.want == http.StatusOK && (!strings.Contains(w.Body.String(), `data-success="/account"`) || w.Header().Get("Content-Security-Policy") == "") {
			t.Fatal("selected GET omitted the bounded relay")
		}
		if tc.want == http.StatusMethodNotAllowed && w.Header().Get("Allow") != "GET, POST" {
			t.Fatal("a new method was implicitly selected")
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, original)
	if w.Code != http.StatusForbidden || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("selected POST did not reach the native denial seam")
	}
}

func TestProxyPreviewDeliversOnlyFreshTypedOriginalCookies(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		name := "browser"
		if choice == session.PersistentSession {
			name = "persistent"
		}
		t.Run(name, func(t *testing.T) {
			c, base, r, device := proxyPreviewFixture(t)
			out, _, cutoff := signinDeliveryResult(t, base, choice)
			out.Session.DeliveryValidUntil = cutoff
			calls := 0
			c.Complete = func(ctx context.Context, flow identity.PreAuthTransactionID, in oauthproxy.PreviewCompletionRequest, network, actualDevice string) (oauth.SigninCallbackResult, error) {
				calls++
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("completion context is unbounded")
				}
				if flow != "AQEBAQEBAQEBAQEBAQEBAQ" || in.Origin != "https://app.example" || in.FlowCookie.Token() != strings.Repeat("B", 42)+"A" || base64.RawURLEncoding.EncodeToString(in.Envelope) != "AQID" || network != "192.0.2.1" || actualDevice != device.DeviceID() {
					t.Fatal("completion lost original trusted browser inputs")
				}
				return out, nil
			}
			w := serveProxyPreview(t, c, r)
			if w.Code != 204 || w.Body.Len() != 0 || calls != 1 || w.Header().Get("Location") != "" {
				t.Fatal("fresh completion did not produce only empty success", w.Code)
			}
			response := w.Result()
			defer response.Body.Close()
			cookies := response.Cookies()
			if len(cookies) != 3 {
				t.Fatal("completion did not deliver exactly auth, CSRF and flow expiry cookies")
			}
			values := map[string]*http.Cookie{}
			for _, cookie := range cookies {
				values[cookie.Name] = cookie
			}
			if values["__Host-identity_session"] == nil || values["__Host-identity_csrf"] == nil || values["__Host-identity_flow"] == nil {
				t.Fatal("completion changed cookie roles")
			}
			original, err := out.Session.Session.Bindings()
			if err != nil {
				t.Fatal(err)
			}
			authentication, err := session.ParseToken(values["__Host-identity_session"].Value)
			if err != nil {
				t.Fatal("authentication cookie lost canonical custody")
			}
			lookup, _ := session.NewDigestKey(1, []byte(strings.Repeat("l", 32)))
			digest, err := authentication.Digest(lookup, string(original.TenantID))
			if err != nil || digest != original.Lookup {
				t.Fatal("completion replaced original authentication custody")
			}
			csrf, err := session.ParseCSRFToken(values["__Host-identity_csrf"].Value)
			if err != nil {
				t.Fatal("CSRF cookie lost canonical custody")
			}
			csrfKey, _ := session.NewCSRFKey(2, []byte(strings.Repeat("c", 32)))
			binding := session.CSRFBinding{TenantID: original.TenantID, SessionID: original.SessionID, SessionVersion: original.Version}
			if out.Session.Session.CSRFState().Check(binding, csrf, csrfKey) != nil {
				t.Fatal("completion replaced original CSRF custody")
			}
			if _, err := out.Session.Token.Reveal(); err == nil {
				t.Fatal("completion retained authentication delivery permission")
			}
			if _, err := out.CSRFToken.Reveal(); err == nil {
				t.Fatal("completion retained CSRF delivery permission")
			}
			if values["__Host-identity_flow"].Value != "" || values["__Host-identity_flow"].MaxAge != -1 {
				t.Fatal("completion failed original flow expiry")
			}
			flowExpiry, _ := c.FlowCookie.DeletionAttributes()
			if values["__Host-identity_flow"].String() != flowExpiry.String() {
				t.Fatal("completion changed original flow cookie deletion scope")
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("completion lost fixed response protections")
			}
		})
	}
}

func TestProxyPreviewRejectsTransportBeforeNative(t *testing.T) {
	cases := map[string]func(*http.Request){
		"get":             func(r *http.Request) { r.Method = http.MethodGet },
		"options":         func(r *http.Request) { r.Method = http.MethodOptions },
		"query":           func(r *http.Request) { r.URL.RawQuery = "flow=other"; r.RequestURI = r.URL.RequestURI() },
		"path":            func(r *http.Request) { r.URL.Path += "/"; r.RequestURI = r.URL.RequestURI() },
		"encoded path":    func(r *http.Request) { r.URL.RawPath = "/%63omplete"; r.RequestURI = r.URL.RequestURI() },
		"host":            func(r *http.Request) { r.Host = "other.example" },
		"http":            func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" },
		"foreign origin":  func(r *http.Request) { r.Header.Set("Origin", "https://other.example") },
		"missing origin":  func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Referer", "https://app.example/complete") },
		"authorization":   func(r *http.Request) { r.Header.Set("Authorization", "Bearer private native detail") },
		"csrf authority":  func(r *http.Request) { r.Header.Set("X-CSRF-Token", "private native detail") },
		"idempotency":     func(r *http.Request) { r.Header.Set("Idempotency-Key", "key") },
		"missing cookies": func(r *http.Request) { r.Header.Del("Cookie") },
		"form":            func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			c, _, r, _ := proxyPreviewFixture(t)
			calls := 0
			c.Complete = func(context.Context, identity.PreAuthTransactionID, oauthproxy.PreviewCompletionRequest, string, string) (oauth.SigninCallbackResult, error) {
				calls++
				return oauth.SigninCallbackResult{}, nil
			}
			alter(r)
			w := serveProxyPreview(t, c, r)
			if calls != 0 || w.Code < 400 {
				t.Fatal("invalid transport reached native completion", w.Code)
			}
			requireNoSigninCredentials(t, w)
			if w.Header().Get("Location") != "" || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("rejection unlocked navigation or CORS")
			}
		})
	}
}

func TestProxyPreviewClosedJSONAndCanonicalHandoff(t *testing.T) {
	for _, body := range []string{
		`{"flow":"AQEBAQEBAQEBAQEBAQEBAQ","envelope":"AQID","origin":"https://app.example"}`,
		`{"Flow":"AQEBAQEBAQEBAQEBAQEBAQ","envelope":"AQID"}`,
		`{"flow":"AQEBAQEBAQEBAQEBAQEBAQ","flow":"AQEBAQEBAQEBAQEBAQEBAQ","envelope":"AQID"}`,
		`{"flow":"AQEBAQEBAQEBAQEBAQEBAQ","envelope":null}`,
		`{"flow":"AQEBAQEBAQEBAQEBAQEBAQ","envelope":"AQID="}`,
		`{"flow":"AQEBAQEBAQEBAQEBAQEBAQ","envelope":"AB"}`,
		`{"flow":"AQEBAQEBAQEBAQEBAQEBAQ","envelope":"` + strings.Repeat("A", 10924) + `"}`,
		`{"flow":"AQEBAQEBAQEBAQEBAQEBAQ","envelope":"AQID"} {}`,
	} {
		t.Run(body[:min(len(body), 80)], func(t *testing.T) {
			c, _, r, _ := proxyPreviewFixture(t)
			calls := 0
			c.Complete = func(context.Context, identity.PreAuthTransactionID, oauthproxy.PreviewCompletionRequest, string, string) (oauth.SigninCallbackResult, error) {
				calls++
				return oauth.SigninCallbackResult{}, nil
			}
			r.Body, r.ContentLength = io.NopCloser(strings.NewReader(body)), int64(len(body))
			w := serveProxyPreview(t, c, r)
			if calls != 0 || w.Code != 400 {
				t.Fatal("noncanonical handoff reached native completion", w.Code)
			}
			requireNoSigninCredentials(t, w)
		})
	}
}

func TestProxyPreviewRejectsNondeliverableNativeOutput(t *testing.T) {
	for _, name := range []string{"replay", "unknown", "missing cutoff", "expired cutoff", "wrong provider", "wrong redirect", "cancelled", "expired during completion", "denied", "invalid", "private error"} {
		t.Run(name, func(t *testing.T) {
			c, base, r, _ := proxyPreviewFixture(t)
			out, _, cutoff := signinDeliveryResult(t, base, session.BrowserSession)
			out.Session.DeliveryValidUntil = cutoff
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			var failure error
			c.Complete = func(context.Context, identity.PreAuthTransactionID, oauthproxy.PreviewCompletionRequest, string, string) (oauth.SigninCallbackResult, error) {
				switch name {
				case "replay":
					out.Session.Replayed = true
				case "unknown":
					out.Session.CommitOutcome = identity.CommitOutcomeUnknown
				case "missing cutoff":
					out.Session.DeliveryValidUntil = time.Time{}
				case "expired cutoff":
					out.Session.DeliveryValidUntil = c.Now()
				case "wrong provider":
					c.ProviderID = "other"
				case "cancelled":
					cancel()
				case "expired during completion":
					now := cutoff
					c.Now = func() time.Time { return now }
				case "denied":
					failure = oauthproxy.CompletionDenied
				case "invalid":
					failure = oauthproxy.CompletionInvalid
				case "private error":
					failure = errors.New("private native detail")
				}
				return out, failure
			}
			// The handler owns a configuration snapshot; change the configured
			// expectation before construction rather than mutating that snapshot.
			if name == "wrong provider" {
				c.ProviderID = "other"
			}
			if name == "wrong redirect" {
				c.Endpoint = "https://app.example/other"
				r.URL.Path = "/other"
				r.RequestURI = r.URL.RequestURI()
			}
			if name == "expired during completion" {
				now := c.Now()
				c.Now = func() time.Time { return now }
				original := c.Complete
				c.Complete = func(ctx context.Context, id identity.PreAuthTransactionID, in oauthproxy.PreviewCompletionRequest, network, device string) (oauth.SigninCallbackResult, error) {
					now = cutoff
					return original(ctx, id, in, network, device)
				}
			}
			w := serveProxyPreview(t, c, r)
			if w.Code < 400 {
				t.Fatal("nondeliverable native result became success", w.Code)
			}
			requireNoSigninCredentials(t, w)
			if name == "denied" && w.Code != 403 || name == "invalid" && w.Code != 400 {
				t.Fatal("native sentinel lost its stable redacted status", w.Code)
			}
		})
	}
}
