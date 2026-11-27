package oauthhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

type oneTapRedirectStartProbe struct {
	calls   int
	last    onetap.BrowserStartRequestSpec
	result  oauthhttp.OneTapRedirectStartHTTPResult
	err     error
	bounded bool
	cancel  context.CancelFunc
}

func (p *oneTapRedirectStartProbe) start(ctx context.Context, request onetap.BrowserRedirectStartRequest) (oauthhttp.OneTapRedirectStartHTTPResult, error) {
	p.calls++
	p.last, _ = request.Bindings()
	_, p.bounded = ctx.Deadline()
	if p.cancel != nil {
		p.cancel()
	}
	return p.result, p.err
}

func oneTapRedirectStartFixture(t *testing.T) (oauthhttp.OneTapRedirectStartConfig, *oneTapRedirectStartProbe, *signinStartRate, *http.Cookie, session.BrowserDevice) {
	t.Helper()
	base, popup, rate, deviceCookie, device := oneTapStartFixture(t)
	endpoint := string(base.Origin) + "/v1/oauth/onetap-callback"
	policy, err := session.NewOneTapRedirectFrontchannelCookiePolicy(string(base.Origin), endpoint)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := policy.Attributes(base.Now(), popup.result.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	p := &oneTapRedirectStartProbe{result: oauthhttp.OneTapRedirectStartHTTPResult{CommandID: popup.result.CommandID, Outcome: identity.CommitOutcomeCommitted,
		Projection: onetap.BrowserRedirectStartProjection{Experience: onetap.BrowserStartRedirectButton, ClientID: base.ClientID, LoginURI: endpoint, Nonce: popup.result.Nonce, State: string(popup.result.FlowID), AllowedParentOrigin: string(base.Origin), IssuedAt: base.Now(), ExpiresAt: popup.result.ExpiresAt, Button: onetap.ButtonProjection{UXMode: onetap.ButtonRedirect, Type: onetap.ButtonStandard, Theme: onetap.ButtonOutline, Size: onetap.ButtonLarge, Width: 400}}, Cookie: cookie, Token: popup.result.Token}}
	c := oauthhttp.OneTapRedirectStartConfig{Network: base.Network, ProviderID: base.ProviderID, ClientID: base.ClientID, CallbackURL: endpoint, Start: p.start, Rate: base.Rate, Device: base.Device, Origin: base.Origin, Lifetime: base.Lifetime, Now: base.Now, MaximumDuration: base.MaximumDuration}
	return c, p, rate, deviceCookie, device
}

func serveOneTapRedirectStart(t *testing.T, c oauthhttp.OneTapRedirectStartConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := oauthhttp.NewOneTapRedirectStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOneTapRedirectStartDeliversOriginalProjectionAndPathCookie(t *testing.T) {
	for _, remember := range []struct {
		suffix string
		choice session.RememberChoice
	}{{"", session.PersistentSession}, {`,"remember":false`, session.BrowserSession}, {`,"remember":true`, session.PersistentSession}} {
		c, p, rate, cookie, device := oneTapRedirectStartFixture(t)
		body := strings.TrimSuffix(oneTapButtonBody, "}") + remember.suffix + "}"
		w := serveOneTapRedirectStart(t, c, oneTapStartRequest(body, cookie))
		if w.Code != 200 || p.calls != 1 || !p.bounded || len(rate.requests) != 1 {
			t.Fatal("redirect start did not execute one bounded admitted call", w.Code)
		}
		if p.last.TenantID != "tenant" || p.last.Origin != string(c.Origin) || p.last.Network != "192.0.2.1" || p.last.Device != device.DeviceID() || p.last.Remember.Choice() != remember.choice {
			t.Fatal("redirect request changed trusted attribution or Remember choice")
		}
		key, _ := identity.NewIdempotencyKey([]byte("Original-Key_123"))
		want, _ := key.Digest([32]byte{1})
		got, _ := p.last.Key.Digest([32]byte{1})
		if got != want {
			t.Fatal("redirect retry key was replaced")
		}
		selected, err := p.last.Options.Projection()
		if err != nil || selected.Experience != onetap.BrowserStartRedirectButton || selected.Button == nil || selected.Prompt != nil || *selected.Button != p.result.Projection.Button {
			t.Fatal("redirect request did not retain exclusive button options", err)
		}
		var projection onetap.BrowserRedirectStartProjection
		if json.Unmarshal(w.Body.Bytes(), &projection) != nil || !reflect.DeepEqual(projection, p.result.Projection) {
			t.Fatal("redirect response changed original typed GIS projection")
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != "__Secure-identity_frontchannel" || cookies[0].Path != "/v1/oauth/onetap-callback" || cookies[0].SameSite != http.SameSiteNoneMode || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Value == "" || !cookies[0].Expires.Equal(projection.ExpiresAt) {
			t.Fatal("redirect response lost exact original path-bound cookie")
		}
		if strings.Contains(w.Body.String(), cookies[0].Value) || strings.Contains(w.Body.String(), "token") || strings.Contains(w.Body.String(), "device") || w.Header().Get("Location") != "" {
			t.Fatal("redirect response disclosed bearer/device or navigated")
		}
		if _, err := p.result.Token.Reveal(); err == nil {
			t.Fatal("delivered redirect bearer remained revealable")
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatal("redirect response did not retain private response policy")
		}
	}
}

func TestOneTapRedirectStartFeatureDocumentsExactButton(t *testing.T) {
	c, p, _, device, _ := oneTapRedirectStartFixture(t)
	feature, err := oauthhttp.NewOneTapRedirectStartFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "One Tap", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Paths map[string]map[string]struct {
			RequestBody struct {
				Content map[string]struct {
					Schema struct {
						Required   []string                   `json:"required"`
						Properties map[string]json.RawMessage `json:"properties"`
					} `json:"schema"`
				} `json:"content"`
			} `json:"requestBody"`
			Responses map[string]json.RawMessage `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(document.JSON(), &wire); err != nil || len(wire.Paths) != 1 {
		t.Fatal("document must select one route", err)
	}
	op := wire.Paths["/v1/oauth/onetap-start"]["post"]
	request := op.RequestBody.Content["application/json"].Schema
	if len(request.Required) != 1 || request.Required[0] != "button" || request.Properties["button"] == nil || request.Properties["prompt"] != nil {
		t.Fatal("wrong request projection for the redirect button")
	}
	if success := string(op.Responses["200"]); !strings.Contains(success, `"login_uri"`) || !strings.Contains(success, `"state"`) || !strings.Contains(success, `"const":"redirect"`) || !strings.Contains(success, "SameSite=None") || strings.Contains(success, `"popup"`) {
		t.Fatal("wrong documented redirect projection or cookie")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, oneTapStartRequest(oneTapButtonBody, device))
	if w.Code != http.StatusOK || p.calls != 1 {
		t.Fatal("selected redirect Start did not execute", w.Code)
	}
}

func TestOneTapRedirectStartRejectsUntrustedOrNonButtonInput(t *testing.T) {
	for _, body := range []string{oneTapPromptBody, `{}`, `{"button":null}`, `{"button":{"type":"standard","theme":"outline","size":"large","ux_mode":"redirect"}}`, strings.TrimSuffix(oneTapButtonBody, "}") + `,"prompt":{"context":"signin","cancelOnTapOutside":true}}`, strings.TrimSuffix(oneTapButtonBody, "}") + `,"callback":"https://foreign.example"}`, strings.TrimSuffix(oneTapButtonBody, "}") + `,"state":"chosen"}`, strings.TrimSuffix(oneTapButtonBody, "}") + `,"provider":"google"}`, strings.TrimSuffix(oneTapButtonBody, "}") + `,"remember":null}`, oneTapButtonBody + `{}`, `{"button":{"type":"standard","theme":"outline","size":"large","width":401}}`, strings.Repeat(" ", 16384) + oneTapButtonBody} {
		c, p, rate, cookie, _ := oneTapRedirectStartFixture(t)
		w := serveOneTapRedirectStart(t, c, oneTapStartRequest(body, cookie))
		if w.Code < 400 || p.calls != 0 || len(rate.requests) != 0 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("invalid redirect input reached admission/native start", w.Code)
		}
	}
	for _, alter := range []func(*http.Request){func(r *http.Request) { r.Header.Del("Origin") }, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }, func(r *http.Request) { r.Header.Del("Idempotency-Key") }, func(r *http.Request) { r.Header.Add("Idempotency-Key", "duplicate") }, func(r *http.Request) { r.Header.Del("Cookie") }, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "alternate") }, func(r *http.Request) { r.URL.RawQuery = "mode=redirect" }, func(r *http.Request) { r.Method = http.MethodGet }, func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "__Secure-identity_frontchannel", Value: "first"})
		r.AddCookie(&http.Cookie{Name: "__Secure-identity_frontchannel", Value: "second"})
	}} {
		c, p, rate, cookie, _ := oneTapRedirectStartFixture(t)
		r := oneTapStartRequest(oneTapButtonBody, cookie)
		alter(r)
		w := serveOneTapRedirectStart(t, c, r)
		if w.Code < 400 || p.calls != 0 || len(rate.requests) != 0 || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("untrusted redirect envelope reached native start", w.Code)
		}
	}
}

func TestOneTapRedirectStartRejectsNonfreshAndMisboundNativeProjection(t *testing.T) {
	for _, mode := range []string{"error", "replayed", "unknown", "command", "client", "endpoint", "origin", "state", "nonce", "zero-nonce", "expired", "issued-future", "lifetime", "experience", "button", "cookie-path", "cookie-samesite", "cookie-expiry", "cookie-value", "cookie-unparsed", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, cookie, _ := oneTapRedirectStartFixture(t)
			r := oneTapStartRequest(oneTapButtonBody, cookie)
			switch mode {
			case "error":
				p.err = errors.New("private failure")
			case "replayed":
				p.result.Replayed = true
			case "unknown":
				p.result.Outcome = identity.CommitOutcomeUnknown
			case "command":
				p.result.CommandID = ""
			case "client":
				p.result.Projection.ClientID = "other"
			case "endpoint":
				p.result.Projection.LoginURI += "/other"
			case "origin":
				p.result.Projection.AllowedParentOrigin = "https://foreign.example"
			case "state":
				p.result.Projection.State = "not-canonical"
			case "nonce":
				p.result.Projection.Nonce = "not-canonical"
			case "zero-nonce":
				p.result.Projection.Nonce = strings.Repeat("A", 43)
			case "expired":
				p.result.Projection.ExpiresAt = c.Now()
			case "issued-future":
				p.result.Projection.IssuedAt = c.Now().Add(time.Second)
			case "lifetime":
				p.result.Projection.IssuedAt = c.Now().Add(-time.Minute)
			case "experience":
				p.result.Projection.Experience = onetap.BrowserStartPopupButton
			case "button":
				p.result.Projection.Button.Width = 399
			case "cookie-path":
				p.result.Cookie.Path = "/other"
			case "cookie-samesite":
				p.result.Cookie.SameSite = http.SameSiteLaxMode
			case "cookie-expiry":
				p.result.Cookie.Expires = p.result.Cookie.Expires.Add(time.Second)
			case "cookie-value":
				p.result.Cookie.Value = "secret"
			case "cookie-unparsed":
				p.result.Cookie.Unparsed = []string{"secret"}
			case "cancelled":
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				p.cancel = cancel
			}
			w := serveOneTapRedirectStart(t, c, r)
			if w.Code < 400 || p.calls != 1 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "nonce") || strings.Contains(w.Body.String(), "private") {
				t.Fatal("misbound redirect result disclosed custody", w.Code)
			}
			if _, err := p.result.Token.Reveal(); err != nil {
				t.Fatal("rejected redirect result consumed its token")
			}
		})
	}
}

func TestOneTapRedirectStartKeepsActualResponseCommitCustody(t *testing.T) {
	for _, mode := range []string{"expiry", "cancel", "body", "status", "remaining"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, cookie, _ := oneTapRedirectStartFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			r := oneTapStartRequest(oneTapButtonBody, cookie)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			h, err := oauthhttp.NewOneTapRedirectStartHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			h, err = identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "late-redirect-custody", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(&oneTapCommitWriter{ResponseWriter: w, write: func(body []byte) (int, error) {
						switch mode {
						case "expiry":
							now = p.result.Projection.ExpiresAt
						case "cancel":
							cancel()
						case "body":
							body = []byte(`{"forged":true}`)
						case "status":
							w.WriteHeader(202)
						case "remaining":
							now = p.result.Projection.ExpiresAt.Add(-3 * time.Second)
						}
						w.Header().Set("Set-Cookie", "injected=secret")
						w.Header().Set("Location", "https://foreign.example")
						return w.Write(body)
					}}, r)
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "remaining" {
				cookies := w.Result().Cookies()
				if w.Code != 200 || len(cookies) != 1 || cookies[0].MaxAge != 3 || !cookies[0].Expires.Equal(p.result.Projection.ExpiresAt) || strings.Contains(cookies[0].Name, "injected") {
					t.Fatal("redirect response renewed or lost original lifetime", w.Code)
				}
				return
			}
			if w.Code != 503 || p.calls != 1 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" || strings.Contains(w.Body.String(), "nonce") {
				t.Fatal("late response change disclosed redirect custody", w.Code)
			}
			if _, err := p.result.Token.Reveal(); err != nil {
				t.Fatal("late rejection consumed token")
			}
		})
	}
}

func TestOneTapRedirectStartSharesRateDenialAndDoesNotRetryLostIO(t *testing.T) {
	c, p, rate, cookie, _ := oneTapRedirectStartFixture(t)
	rate.fail = true
	w := serveOneTapRedirectStart(t, c, oneTapStartRequest(oneTapButtonBody, cookie))
	if w.Code != 503 || p.calls != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("redirect rate outage failed open", w.Code)
	}
	rate.fail = false
	h, err := oauthhttp.NewOneTapRedirectStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	lost := &oneTapLostWriter{header: make(http.Header)}
	h.ServeHTTP(lost, oneTapStartRequest(oneTapButtonBody, cookie))
	if p.calls != 1 || lost.writes != 1 {
		t.Fatal("lost redirect response retried Start or write")
	}
	second := httptest.NewRecorder()
	h.ServeHTTP(second, oneTapStartRequest(oneTapButtonBody, cookie))
	if p.calls != 2 || second.Code != 503 || second.Header().Get("Set-Cookie") != "" {
		t.Fatal("redirect repeated response redelivered token", second.Code)
	}
}

func TestOneTapRedirectStartRejectsIncompleteOrNonexactComposition(t *testing.T) {
	for _, alter := range []func(*oauthhttp.OneTapRedirectStartConfig){func(c *oauthhttp.OneTapRedirectStartConfig) { c.Start = nil }, func(c *oauthhttp.OneTapRedirectStartConfig) { c.Rate = nil }, func(c *oauthhttp.OneTapRedirectStartConfig) { c.Now = nil }, func(c *oauthhttp.OneTapRedirectStartConfig) { c.MaximumDuration = 0 }, func(c *oauthhttp.OneTapRedirectStartConfig) { c.ProviderID = "other" }, func(c *oauthhttp.OneTapRedirectStartConfig) { c.ClientID = "" }, func(c *oauthhttp.OneTapRedirectStartConfig) {
		c.CallbackURL = "https://foreign.example/v1/oauth/onetap-callback"
	}, func(c *oauthhttp.OneTapRedirectStartConfig) { c.CallbackURL += "?alias=true" }, func(c *oauthhttp.OneTapRedirectStartConfig) { c.CallbackURL = string(c.Origin) + "/other" }, func(c *oauthhttp.OneTapRedirectStartConfig) { c.Origin = "http://app.example" }, func(c *oauthhttp.OneTapRedirectStartConfig) { c.Lifetime = session.LifetimeConfig{} }} {
		c, _, _, _, _ := oneTapRedirectStartFixture(t)
		alter(&c)
		if h, err := oauthhttp.NewOneTapRedirectStartHandler(c); h != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("incomplete redirect composition enabled", err)
		}
	}
}
