package oauthhttp_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/session"
)

const oneTapRedirectCallbackForm = "state=AQEBAQEBAQEBAQEBAQEBAQ&credential=synthetic-google-credential&g_csrf_token=original.google_csrf!"

// The native boundary is deliberately synthetic: the real resolver and parser
// are exercised here, not Google's signature verifier or a live browser.
type oneTapRedirectCallbackProbe struct {
	calls   int
	last    oauthhttp.OneTapRedirectCallbackHTTPInput
	bounded bool
	result  oauthhttp.OneTapCallbackHTTPResult
	err     error
	before  func()
}

func (p *oneTapRedirectCallbackProbe) complete(ctx context.Context, in oauthhttp.OneTapRedirectCallbackHTTPInput) (oauthhttp.OneTapCallbackHTTPResult, error) {
	p.calls++
	p.last = in
	_, p.bounded = ctx.Deadline()
	if p.before != nil {
		p.before()
	}
	return p.result, p.err
}

func oneTapRedirectCallbackFixture(t *testing.T) (oauthhttp.OneTapRedirectCallbackConfig, *oneTapRedirectCallbackProbe, *signinStartRate, *http.Request, oauthhttp.OneTapCallbackConfig) {
	t.Helper()
	popup, _, rate, _, _ := oneTapCallbackHTTPFixture(t)
	callback := "https://app.example/v1/oauth/onetap-callback"
	frontchannel, err := session.NewOneTapRedirectFrontchannelCookiePolicy(string(popup.Origin), callback)
	if err != nil {
		t.Fatal(err)
	}
	p := &oneTapRedirectCallbackProbe{err: errors.New("private native detail")}
	c := oauthhttp.OneTapRedirectCallbackConfig{Network: popup.Network, Provider: popup.Provider, Complete: p.complete, Rate: popup.Rate, Cookie: popup.Cookie, FrontchannelCookie: frontchannel, CSRFCookie: popup.CSRFCookie, Origin: popup.Origin, TenantID: popup.TenantID, Audience: popup.Audience, CallbackURL: callback, Now: popup.Now, MaximumDuration: time.Second}
	r := httptest.NewRequest(http.MethodPost, callback, strings.NewReader(oneTapRedirectCallbackForm))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "[::ffff:192.0.2.1]:1234"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "__Secure-identity_frontchannel", Value: strings.Repeat("A", 43)})
	r.AddCookie(&http.Cookie{Name: "g_csrf_token", Value: "original.google_csrf!"})
	return c, p, rate, r, popup
}

func oneTapRedirectCallbackServe(t *testing.T, c oauthhttp.OneTapRedirectCallbackConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := oauthhttp.NewOneTapRedirectCallbackHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOneTapRedirectCallbackHTTPBindsTrustedEndpointAndOriginalCookie(t *testing.T) {
	c, p, rate, r, _ := oneTapRedirectCallbackFixture(t)
	r.Header.Set("Origin", "https://accounts.google.com")
	r.Header.Set("Referer", "https://untrusted.example/")
	body := oneTapRedirectCallbackForm + "&client_id=foreign&select_by=untrusted&redirect=https%3A%2F%2Fevil.example&device=replacement&future_field=ignored"
	r.Body, r.ContentLength = io.NopCloser(strings.NewReader(body)), int64(len(body))
	p.before = func() {
		if string(p.last.Callback.Credential.IDToken) != "synthetic-google-credential" {
			t.Fatal("borrowed credential changed")
		}
	}
	w := oneTapRedirectCallbackServe(t, c, r)
	if w.Code != 503 || p.calls != 1 || !p.bounded || len(rate.requests) != 1 {
		t.Fatal("valid form failed bounded native admission", w.Code)
	}
	if p.last.FlowID != "AQEBAQEBAQEBAQEBAQEBAQ" || p.last.FlowCookie.Token() != strings.Repeat("A", 43) || p.last.Callback.Origin != string(c.Origin) || p.last.Callback.Redirect != c.CallbackURL || p.last.Network != netip.MustParseAddr("192.0.2.1") {
		t.Fatal("untrusted input replaced configured callback scope")
	}
	if len(p.last.Callback.CSRFCookies) != 1 || p.last.Callback.CSRFCookies[0] != "original.google_csrf!" || len(p.last.Callback.CSRFBody) != 1 || p.last.Callback.CSRFBody[0] != "original.google_csrf!" {
		t.Fatal("Google double-submit changed")
	}
	for _, b := range p.last.Callback.Credential.IDToken {
		if b != 0 {
			t.Fatal("borrowed credential survived request")
		}
	}
	requireNoSigninCredentials(t, w)
	if strings.Contains(w.Body.String(), "private native detail") || strings.Contains(w.Body.String(), "synthetic-google-credential") {
		t.Fatal("private input escaped")
	}
}

func TestOneTapRedirectCallbackHTTPRejectsMalformedAndSubstitutedInputBeforeNative(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*http.Request)
	}{
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer replacement") }},
		{"key", func(r *http.Request) { r.Header.Set("Idempotency-Key", "replacement") }},
		{"header-csrf", func(r *http.Request) { r.Header.Set("X-CSRF-Token", "replacement") }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "state=replacement"; r.RequestURI = r.URL.RequestURI() }},
		{"path", func(r *http.Request) { r.URL.Path += "/"; r.RequestURI = r.URL.RequestURI() }},
		{"escaped-path", func(r *http.Request) {
			r.URL.RawPath = "/v1/oauth/onetap%2dcallback"
			r.RequestURI = r.URL.RequestURI()
		}},
		{"method", func(r *http.Request) { r.Method = http.MethodGet }},
		{"foreign-host", func(r *http.Request) { r.Host = "foreign.example" }},
		{"http", func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }},
		{"peer", func(r *http.Request) { r.RemoteAddr = "invalid" }},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"Credential": {"replacement"}} }},
		{"json", func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }},
		{"missing-frontchannel", func(r *http.Request) { r.Header.Set("Cookie", "g_csrf_token=original.google_csrf!") }},
		{"missing-google", func(r *http.Request) {
			r.Header.Set("Cookie", "__Secure-identity_frontchannel="+strings.Repeat("A", 43))
		}},
		{"lax-fallback", func(r *http.Request) {
			r.Header.Set("Cookie", "__Host-identity_flow="+strings.Repeat("A", 43)+"; __Host-identity_device=replacement; g_csrf_token=original.google_csrf!")
		}},
		{"duplicate-frontchannel", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Secure-identity_frontchannel", Value: strings.Repeat("A", 43)})
		}},
		{"alias-frontchannel", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__secure-identity_frontchannel", Value: strings.Repeat("A", 43)})
		}},
		{"duplicate-google", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "g_csrf_token", Value: "original.google_csrf!"}) }},
		{"quoted-google", func(r *http.Request) {
			r.Header.Set("Cookie", "__Secure-identity_frontchannel="+strings.Repeat("A", 43)+"; g_csrf_token=\"original.google_csrf!\"")
		}},
		{"google-mismatch", func(r *http.Request) {
			r.Header.Set("Cookie", "__Secure-identity_frontchannel="+strings.Repeat("A", 43)+"; g_csrf_token=other")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p, rate, r, _ := oneTapRedirectCallbackFixture(t)
			tc.alter(r)
			w := oneTapRedirectCallbackServe(t, c, r)
			if w.Code < 400 || p.calls != 0 || len(rate.requests) != 0 {
				t.Fatal("invalid input reached native/rate", w.Code)
			}
			requireNoSigninCredentials(t, w)
		})
	}
	for _, body := range []string{
		"", strings.Replace(oneTapRedirectCallbackForm, "state=", "flowId=", 1), strings.Replace(oneTapRedirectCallbackForm, "AQEBAQEBAQEBAQEBAQEBAQ", "AQEBAQEBAQEBAQEBAQEBAR", 1),
		oneTapRedirectCallbackForm + "&state=AQEBAQEBAQEBAQEBAQEBAQ", oneTapRedirectCallbackForm + "&Credential=duplicate", oneTapRedirectCallbackForm + "&g_csrf_token=duplicate", oneTapRedirectCallbackForm + "&bad=%ZZ",
		strings.Replace(oneTapRedirectCallbackForm, "synthetic-google-credential", "", 1), strings.Replace(oneTapRedirectCallbackForm, "synthetic-google-credential", strings.Repeat("A", 16385), 1), strings.Replace(oneTapRedirectCallbackForm, "original.google_csrf!", strings.Repeat("A", 1025), 1),
	} {
		c, p, rate, r, _ := oneTapRedirectCallbackFixture(t)
		c.Network.Limits.MaximumBodyBytes, c.Network.Limits.MaximumDecodedBytes = 32768, 32768
		r.Body, r.ContentLength = io.NopCloser(strings.NewReader(body)), int64(len(body))
		w := oneTapRedirectCallbackServe(t, c, r)
		if w.Code != 400 || p.calls != 0 || len(rate.requests) != 0 {
			t.Fatal("malformed form reached native/rate", w.Code)
		}
	}
}

func TestOneTapRedirectCallbackHTTPOnlyDeliversFreshNativeCookies(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		c, p, _, r, popup := oneTapRedirectCallbackFixture(t)
		p.result, p.err = oneTapCallbackHTTPResult(t, popup, choice), nil
		original, _ := p.result.Session.Session.Bindings()
		w := oneTapRedirectCallbackServe(t, c, r)
		if w.Code != 200 || w.Body.String() != "{\"status\":\"signed_in\"}\n" || len(w.Header().Values("Set-Cookie")) != 2 || p.calls != 1 {
			t.Fatal("fresh commit did not deliver exact success", w.Code)
		}
		for _, cookie := range w.Result().Cookies() {
			if cookie.Name != "__Host-identity_session" && cookie.Name != "__Host-identity_csrf" || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.HttpOnly != (cookie.Name == "__Host-identity_session") {
				t.Fatal("unexpected callback cookie")
			}
			if choice == session.BrowserSession && (!cookie.Expires.IsZero() || cookie.MaxAge != 0) {
				t.Fatal("browser session became persistent")
			}
			if choice == session.PersistentSession && !cookie.Expires.Equal(original.IssuedAt.Add(original.Remember.AbsoluteTTL())) {
				t.Fatal("original expiry changed")
			}
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Location") != "" {
			t.Fatal("redirect response leaked or cached")
		}
	}
}

func TestOneTapRedirectCallbackHTTPNoCookiesOnReplayLateOrCancelledCompletion(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "late", "cancelled", "error"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, r, popup := oneTapRedirectCallbackFixture(t)
			p.result, p.err = oneTapCallbackHTTPResult(t, popup, session.BrowserSession), nil
			switch mode {
			case "replay":
				p.result.Session.Replayed = true
			case "unknown":
				p.result.Session.CommitOutcome = identity.CommitOutcomeUnknown
			case "cancelled":
				ctx, cancel := context.WithCancel(r.Context())
				r = r.WithContext(ctx)
				p.before = cancel
			case "error":
				p.err = errors.New("private")
			}
			// The configured clock function closes over this mutable fixture value.
			now := c.Now
			c.Now = func() time.Time {
				if mode == "late" && p.calls > 0 {
					return p.result.Session.DeliveryValidUntil
				}
				return now()
			}
			w := oneTapRedirectCallbackServe(t, c, r)
			if w.Code != 503 || p.calls != 1 {
				t.Fatal("nondeliverable completion became success", w.Code)
			}
			requireNoSigninCredentials(t, w)
		})
	}
}

func TestOneTapRedirectCallbackHTTPRechecksDeliveryAtResponseCommit(t *testing.T) {
	for _, mode := range []string{"deadline", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, r, popup := oneTapRedirectCallbackFixture(t)
			p.result, p.err = oneTapCallbackHTTPResult(t, popup, session.BrowserSession), nil
			now := c.Now()
			c.Now = func() time.Time { return now }
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			h, err := oauthhttp.NewOneTapRedirectCallbackHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "delay-redirect-commit", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(oneTapCallbackHTTPCommitWriter{ResponseWriter: w, before: func() {
						if mode == "deadline" {
							now = p.result.Session.DeliveryValidUntil
						} else {
							cancel()
						}
					}}, r)
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			bound.ServeHTTP(w, r)
			if w.Code != 503 || p.calls != 1 || strings.Contains(w.Body.String(), "signed_in") {
				t.Fatal("late commit leaked success", w.Code)
			}
			requireNoSigninCredentials(t, w)
		})
	}
}

func TestOneTapRedirectCallbackHTTPFailsClosedOnProviderIPAdmissionFailure(t *testing.T) {
	c, p, rate, r, _ := oneTapRedirectCallbackFixture(t)
	rate.fail = true
	w := oneTapRedirectCallbackServe(t, c, r)
	if w.Code != 503 || p.calls != 0 || len(rate.requests) != 1 {
		t.Fatal("failed provider/IP owner reached native", w.Code)
	}
	requireNoSigninCredentials(t, w)
}

func FuzzOneTapRedirectCallbackHTTPForm(f *testing.F) {
	for _, body := range []string{oneTapRedirectCallbackForm, "state=", oneTapRedirectCallbackForm + "&credential=duplicate", oneTapRedirectCallbackForm + "&future=ignored", oneTapRedirectCallbackForm + "&bad=%ZZ"} {
		f.Add(body)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 4096 {
			return
		}
		c, p, _, r, _ := oneTapRedirectCallbackFixture(t)
		r.Body, r.ContentLength = io.NopCloser(strings.NewReader(body)), int64(len(body))
		w := oneTapRedirectCallbackServe(t, c, r)
		if p.calls > 1 || w.Code < 400 {
			t.Fatal("malformed native result admitted delivery")
		}
		requireNoSigninCredentials(t, w)
		for _, b := range p.last.Callback.Credential.IDToken {
			if b != 0 {
				t.Fatal("credential survived handler")
			}
		}
	})
}

func TestOneTapRedirectCallbackHTTPRequiresExactTrustedConfiguration(t *testing.T) {
	for _, callback := range []string{"http://app.example/v1/oauth/onetap-callback", "https://evil.example/v1/oauth/onetap-callback", "https://app.example/other", "https://app.example/v1/oauth/onetap-callback?x=1", "https://app.example/v1/oauth/onetap-callback#fragment"} {
		c, _, _, _, _ := oneTapRedirectCallbackFixture(t)
		c.CallbackURL = callback
		if _, err := oauthhttp.NewOneTapRedirectCallbackHandler(c); err == nil {
			t.Fatal("untrusted callback configuration accepted")
		}
	}
	c, _, _, _, _ := oneTapRedirectCallbackFixture(t)
	c.FrontchannelCookie = session.FrontchannelCookiePolicy{}
	if _, err := oauthhttp.NewOneTapRedirectCallbackHandler(c); err == nil {
		t.Fatal("missing original frontchannel policy accepted")
	}
}
