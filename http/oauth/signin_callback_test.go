package oauthhttp_test

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
)

// These doubles prove transport dispatch, not native state or browser admission.
type callbackOperationProbe struct {
	operation string
	err       error
	calls     int
	last      oauth.Callback
}

func (p *callbackOperationProbe) CallbackOperation(_ context.Context, _ identity.TenantID, c oauth.Callback) (string, error) {
	p.calls++
	p.last = c
	return p.operation, p.err
}

type signinCallbackProbe struct {
	sources, callbacks int
	last               oauth.SigninCallbackRequest
}

func (p *signinCallbackProbe) SigninCallbackRateSource(_ context.Context, r oauth.SigninCallbackRequest) (oauth.CallbackRateContext, error) {
	p.sources++
	p.last = r
	return oauth.CallbackRateContext{ProviderID: "configured", TransactionID: "AQEBAQEBAQEBAQEBAQEBAQ", Lifetime: 5 * time.Minute}, nil
}

func (p *signinCallbackProbe) Callback(_ context.Context, r oauth.SigninCallbackRequest) (oauth.SigninCallbackResult, error) {
	p.callbacks++
	p.last = r
	return oauth.SigninCallbackResult{}, identityhttp.ErrUnavailable
}

func sharedCallbackFixture(t *testing.T, operation string) (oauthhttp.Config, *callbackOperationProbe, *signinCallbackProbe, *callbackProbe, *http.Request, session.BrowserDevice) {
	t.Helper()
	start, _, _, deviceCookie, device := signinStartFixture(t)
	selector := &callbackOperationProbe{operation: operation}
	signin, link := &signinCallbackProbe{}, &callbackProbe{}
	authentication, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	csrf, err := session.NewCSRFCookiePolicy(session.CookieConfig{Name: "__Host-identity_csrf", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	c := oauthhttp.Config{Network: start.Network, Provider: start.Provider, Rate: start.Rate, Cookie: authentication, Origin: start.Origin, CallbackAllowlist: start.CallbackAllowlist, Now: start.Now, MaximumDuration: start.MaximumDuration, Callback: link,
		Signin: &oauthhttp.SigninCallbackConfig{Operations: selector, Source: signin, Complete: signin, FlowCookie: start.FlowCookie, Device: start.Device, CSRFCookie: csrf, Audience: "service-a"}}
	query := url.Values{"code": {"original-provider-code"}, "state": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, "iss": {start.Provider.Issuer}}
	r := httptest.NewRequest(http.MethodGet, "https://app.example/v1/oauth/callback?"+query.Encode(), nil)
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "192.0.2.1:1234"
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: strings.Repeat("A", 43)})
	r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("B", 42) + "A"})
	r.AddCookie(deviceCookie)
	return c, selector, signin, link, r, device
}

func TestSharedCallbackDispatchUsesNativeIntentNotAmbientCookies(t *testing.T) {
	for _, operation := range []string{"identity.oauth.signin-start", "identity.account.link-start"} {
		t.Run(operation, func(t *testing.T) {
			c, selected, signin, link, r, device := sharedCallbackFixture(t, operation)
			h, err := oauthhttp.NewCallbackHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 503 || selected.calls != 1 || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "original-provider-code") {
				t.Fatal("callback did not remain bound to its native routing outcome", w.Code)
			}
			if operation == "identity.oauth.signin-start" {
				if signin.sources != 1 || signin.callbacks != 1 || link.sources != 0 || link.callbacks != 0 || signin.last.Device != device.DeviceID() || signin.last.FlowCookie.Token() != strings.Repeat("B", 42)+"A" {
					t.Fatal("signin was selected by an ambient session or lost original browser custody")
				}
			} else if link.sources != 1 || link.callbacks != 0 || signin.sources != 0 || signin.callbacks != 0 {
				t.Fatal("linking fell through to signin after native denial")
			}
			input, ok := selected.last.Input()
			if !ok || input.Use(t.Context(), func(context.Context, []byte, []byte) error { return nil }) == nil {
				t.Fatal("callback custody survived the handler")
			}
		})
	}
}

func TestSharedCallbackRateDenialsPreserveRetryMetadata(t *testing.T) {
	for _, dimension := range []string{"provider-ip", "original-transaction"} {
		t.Run(dimension, func(t *testing.T) {
			c, selected, signin, link, request, _ := sharedCallbackFixture(t, "identity.oauth.signin-start")
			rateConfig, _, rateBackend, _, _ := signinStartFixture(t)
			c.Rate = rateConfig.Rate
			resolver, err := identityhttp.NewNetworkResolver(c.Network)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := resolver.Resolve(request)
			if err != nil {
				t.Fatal(err)
			}
			wantRetry, wantSources := "20", 0
			if dimension == "provider-ip" {
				for range 30 {
					admitted, err := c.Rate.AdmitProviderIP(t.Context(), facts, "identity.oauth.callback", c.Provider.ID)
					if err != nil || !admitted.Allowed {
						t.Fatal("could not fill original provider/IP budget")
					}
				}
			} else {
				wantRetry, wantSources = "60", 1
				for range 5 {
					admitted, err := c.Rate.AdmitProviderTransaction(t.Context(), facts, "identity.oauth.callback", c.Provider.ID, "AQEBAQEBAQEBAQEBAQEBAQ", 5*time.Minute)
					if err != nil || !admitted.Allowed {
						t.Fatal("could not fill original transaction budget")
					}
				}
			}
			handler, err := oauthhttp.NewCallbackHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != 429 || response.Header().Get("Retry-After") != wantRetry {
				t.Fatal("callback budget denial lost bounded retry metadata", response.Code, response.Header().Get("Retry-After"))
			}
			if selected.calls != wantSources || signin.sources != wantSources || signin.callbacks != 0 || link.sources != 0 || link.callbacks != 0 || len(response.Result().Cookies()) != 0 || response.Header().Get("Location") != "" {
				t.Fatal("rate-denied callback crossed its native admission boundary")
			}
			rateBackend.fail = true
			outage := httptest.NewRecorder()
			handler.ServeHTTP(outage, request.Clone(t.Context()))
			if outage.Code != 503 || outage.Header().Get("Retry-After") != "" || selected.calls != wantSources || signin.sources != wantSources || signin.callbacks != 0 {
				t.Fatal("callback rate outage fabricated retry metadata or reached native completion", outage.Code)
			}
		})
	}
}

func TestSharedCallbackRejectsUnselectedIntentWithoutOwnerFallback(t *testing.T) {
	for _, operation := range []string{"", "identity.password.signin"} {
		c, selected, signin, link, r, _ := sharedCallbackFixture(t, operation)
		h, err := oauthhttp.NewCallbackHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 403 || selected.calls != 1 || signin.sources != 0 || link.sources != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("unselected original intent reached a callback owner", w.Code)
		}
	}
	c, selected, signin, link, r, _ := sharedCallbackFixture(t, "identity.oauth.signin-start")
	selected.err = identity.UnavailableError{}
	h, err := oauthhttp.NewCallbackHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || selected.calls != 1 || signin.sources != 0 || link.sources != 0 {
		t.Fatal("failed routing fell back to another owner", w.Code)
	}
}

func TestSharedCallbackChecksIssuerAndPresentOriginBeforeNativeRouting(t *testing.T) {
	for _, mutation := range []string{"issuer", "origin", "origin-alias", "legacy-origin-alias", "key"} {
		t.Run(mutation, func(t *testing.T) {
			c, selected, signin, link, r, _ := sharedCallbackFixture(t, "identity.oauth.signin-start")
			switch mutation {
			case "issuer":
				q := r.URL.Query()
				q.Set("iss", "https://other.example")
				r.URL.RawQuery = q.Encode()
				r.RequestURI = r.URL.RequestURI()
			case "origin":
				r.Header.Set("Origin", "https://other.example")
			case "origin-alias", "legacy-origin-alias":
				r.Header["origin"] = []string{"https://other.example"}
				if mutation == "legacy-origin-alias" {
					c.Signin = nil
				}
			case "key":
				r.Header.Set("Idempotency-Key", "replacement")
			}
			h, err := oauthhttp.NewCallbackHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || selected.calls != 0 || signin.sources != 0 || link.sources != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("foreign callback reached native routing", w.Code)
			}
		})
	}
}

type callbackReadFromWriter struct{ *httptest.ResponseRecorder }

func (w callbackReadFromWriter) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(w.ResponseRecorder, r)
}

func TestSharedCallbackMiddlewareCannotInjectCookiesThroughWriterInterfaces(t *testing.T) {
	for _, channel := range []string{"flush", "read-from"} {
		t.Run(channel, func(t *testing.T) {
			c, selected, signin, link, r, _ := sharedCallbackFixture(t, "identity.oauth.signin-start")
			h, err := oauthhttp.NewCallbackHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "denied-before-native", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.Header()["set-cookie"] = []string{"__Host-identity_session=not-owned; Secure; HttpOnly; Path=/"}
					w.Header()["location"] = []string{"https://other.example/not-owned"}
					if channel == "flush" {
						w.(http.Flusher).Flush()
					} else {
						_, _ = w.(io.ReaderFrom).ReadFrom(strings.NewReader("denied"))
					}
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			bound.ServeHTTP(callbackReadFromWriter{recorder}, r)
			response := recorder.Result()
			defer response.Body.Close()
			for name := range response.Header {
				if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Location") {
					t.Fatal("middleware committed unowned callback transport", channel)
				}
			}
			if selected.calls != 0 || signin.callbacks != 0 || link.callbacks != 0 {
				t.Fatal("middleware short circuit reached a native callback")
			}
		})
	}
}
