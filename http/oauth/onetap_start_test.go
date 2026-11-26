package oauthhttp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

const oneTapPromptBody = `{"prompt":{"context":"signin","cancelOnTapOutside":true}}`
const oneTapButtonBody = `{"button":{"type":"standard","theme":"outline","size":"large","width":400}}`

// This double owns only the synchronous native port, not flow persistence or
// provider authority. Native Start integration supplies that separate proof.
type oneTapStartProbe struct {
	calls   int
	last    onetap.BrowserStartRequestSpec
	result  oauthhttp.OneTapStartHTTPResult
	err     error
	bounded bool
	cancel  context.CancelFunc
}

func (p *oneTapStartProbe) start(ctx context.Context, request onetap.BrowserStartRequest) (oauthhttp.OneTapStartHTTPResult, error) {
	p.calls++
	p.last, _ = request.Bindings()
	_, p.bounded = ctx.Deadline()
	if p.cancel != nil {
		p.cancel()
	}
	out := p.result
	if out.Options == (onetap.BrowserStartOptions{}) {
		out.Options = p.last.Options
	}
	return out, p.err
}

func oneTapStartFixture(t *testing.T) (oauthhttp.OneTapStartConfig, *oneTapStartProbe, *signinStartRate, *http.Cookie, session.BrowserDevice) {
	t.Helper()
	base, _, rate, cookie, device := signinStartFixture(t)
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	issued, _ := base.FlowCookie.DeletionAttributes()
	issued.MaxAge, issued.Expires = 300, base.Now().Add(5*time.Minute)
	p := &oneTapStartProbe{result: oauthhttp.OneTapStartHTTPResult{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", Outcome: identity.CommitOutcomeCommitted, FlowID: "AgICAgICAgICAgICAgICAg", ClientID: "configured-google-client", Nonce: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("n", 32))), Origin: string(base.Origin), ExpiresAt: issued.Expires, Cookie: issued, Token: token}}
	c := oauthhttp.OneTapStartConfig{Network: base.Network, ProviderID: "google", ClientID: p.result.ClientID, Start: p.start, Rate: base.Rate, FlowCookie: base.FlowCookie, Device: base.Device, Origin: base.Origin, Lifetime: base.Lifetime, Now: base.Now, MaximumDuration: time.Second}
	return c, p, rate, cookie, device
}

func oneTapStartRequest(body string, device *http.Cookie) *http.Request {
	r := signinStartRequest(body, device)
	r.URL.Path = "/v1/oauth/onetap-start"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Del("Cookie")
	r.AddCookie(device)
	return r
}

func serveOneTapStart(t *testing.T, c oauthhttp.OneTapStartConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := oauthhttp.NewOneTapStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestOneTapStartProjectsSelectedOptionsAndOriginalCookieOnce(t *testing.T) {
	for _, body := range []string{oneTapPromptBody, oneTapButtonBody} {
		for _, remember := range []struct {
			suffix string
			choice session.RememberChoice
		}{{"", session.PersistentSession}, {`,"remember":false`, session.BrowserSession}, {`,"remember":true`, session.PersistentSession}} {
			c, p, rate, cookie, device := oneTapStartFixture(t)
			body := strings.TrimSuffix(body, "}") + remember.suffix + "}"
			w := serveOneTapStart(t, c, oneTapStartRequest(body, cookie))
			if w.Code != 200 || p.calls != 1 || !p.bounded || len(rate.requests) != 1 {
				t.Fatal("selected initiation did not reach one bounded admission", w.Code)
			}
			key, _ := identity.NewIdempotencyKey([]byte("Original-Key_123"))
			want, _ := key.Digest([32]byte{1})
			got, _ := p.last.Key.Digest([32]byte{1})
			if p.last.TenantID != "tenant" || p.last.Origin != string(c.Origin) || p.last.Network != "192.0.2.1" || p.last.Device != device.DeviceID() || got != want || p.last.Remember.Choice() != remember.choice {
				t.Fatal("trusted attribution or original Remember choice changed")
			}
			var out struct {
				ClientID  string                        `json:"clientId"`
				Nonce     string                        `json:"nonce"`
				FlowID    string                        `json:"flowId"`
				ExpiresAt time.Time                     `json:"expiresAt"`
				Options   onetap.BrowserStartProjection `json:"options"`
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || json.Unmarshal(w.Body.Bytes(), &fields) != nil || len(fields) != 5 || out.ClientID != p.result.ClientID || out.Nonce != p.result.Nonce || out.FlowID != string(p.result.FlowID) || !out.ExpiresAt.Equal(p.result.ExpiresAt) {
				t.Fatal("response is not the explicit browser projection")
			}
			wantOptions, _ := p.last.Options.Projection()
			wantJSON, _ := json.Marshal(wantOptions)
			gotJSON, _ := json.Marshal(out.Options)
			if string(wantJSON) != string(gotJSON) {
				t.Fatal("options changed at wire boundary")
			}
			cookies := w.Result().Cookies()
			if len(cookies) != 1 || cookies[0].Name != "__Host-identity_flow" || cookies[0].Value == "" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].MaxAge != 300 || !cookies[0].Expires.Equal(p.result.ExpiresAt) {
				t.Fatal("original flow cookie custody changed")
			}
			if _, err := p.result.Token.Reveal(); !errors.Is(err, session.ErrTokenAlreadyRevealed) {
				t.Fatal("transport did not consume exactly one token reveal")
			}
			if strings.Contains(w.Body.String(), cookies[0].Value) || w.Header().Get("Location") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("credential escaped its cookie or response safety was lost")
			}
		}
	}
}

func TestOneTapStartRejectsUntrustedOrUnsupportedIntent(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*http.Request)
	}{
		{"missing-key", func(r *http.Request) { r.Header.Del("Idempotency-Key") }},
		{"duplicate-key", func(r *http.Request) { r.Header.Add("Idempotency-Key", "other") }},
		{"alias-key", func(r *http.Request) { r.Header["idempotency-key"] = []string{"other"} }},
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer unrelated") }},
		{"csrf", func(r *http.Request) { r.Header.Set("X-CSRF-Token", "unrelated") }},
		{"missing-origin", func(r *http.Request) { r.Header.Del("Origin") }},
		{"foreign-origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }},
		{"duplicate-origin", func(r *http.Request) { r.Header.Add("Origin", "https://app.example") }},
		{"plaintext", func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }},
		{"foreign-host", func(r *http.Request) { r.Host = "foreign.example" }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "mode=redirect"; r.RequestURI = r.URL.RequestURI() }},
		{"method", func(r *http.Request) { r.Method = http.MethodGet }},
		{"sibling", func(r *http.Request) { r.URL.Path = "/v1/oauth/signin-start"; r.RequestURI = r.URL.RequestURI() }},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"Extra": []string{"value"}} }},
		{"missing-device", func(r *http.Request) { r.Header.Del("Cookie") }},
		{"forged-device", func(r *http.Request) { r.Header.Set("Cookie", "__Host-identity_device=forged") }},
		{"duplicate-device", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "__Host-identity_device", Value: "duplicate"}) }},
		{"duplicate-flow-cookies", func(r *http.Request) {
			flow := &http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)}
			r.AddCookie(flow)
			r.AddCookie(flow)
		}},
	}
	for _, body := range []string{`{}`, `null`, `{"prompt":null}`, `{"prompt":{"context":"signin"}}`, `{"prompt":{"context":"unknown","cancelOnTapOutside":true}}`, `{"prompt":{"context":"signin","cancelOnTapOutside":null}}`, `{"prompt":{"context":"signin","cancelOnTapOutside":true,"login_hint":"private"}}`, `{"prompt":{"context":"signin","cancelOnTapOutside":true},"button":{"type":"icon","theme":"outline","size":"small"}}`, `{"button":{"type":"standard","theme":"outline","size":"large","width":401}}`, `{"button":{"type":"standard","theme":"outline","size":"large","width":-1}}`, `{"button":{"type":"standard","theme":"outline","size":"large","ux_mode":"redirect"}}`, strings.TrimSuffix(oneTapPromptBody, "}") + `,"remember":null}`, strings.TrimSuffix(oneTapPromptBody, "}") + `,"clientId":"other"}`, strings.TrimSuffix(oneTapPromptBody, "}") + `,"provider":"google"}`, strings.TrimSuffix(oneTapPromptBody, "}") + `,"callback":"https://app.example/callback"}`, strings.TrimSuffix(oneTapPromptBody, "}") + `,"flowId":"AgICAgICAgICAgICAgICAg"}`, strings.TrimSuffix(oneTapPromptBody, "}") + `,"prompt":{"context":"use","cancelOnTapOutside":true}}`, oneTapPromptBody + `{}`, strings.Repeat(" ", 16384) + oneTapPromptBody} {
		cases = append(cases, struct {
			name  string
			alter func(*http.Request)
		}{"body", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(body))
			r.ContentLength = int64(len(body))
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p, rate, device, _ := oneTapStartFixture(t)
			r := oneTapStartRequest(oneTapPromptBody, device)
			tc.alter(r)
			w := serveOneTapStart(t, c, r)
			if w.Code < 400 || p.calls != 0 || len(rate.requests) != 0 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "nonce") {
				t.Fatal("invalid initiation reached owner or disclosed custody", w.Code)
			}
		})
	}
}

func TestOneTapStartCanReplaceAnAmbientFlowOnADeliberateNewAttempt(t *testing.T) {
	c, p, rate, device, _ := oneTapStartFixture(t)
	h, err := oauthhttp.NewOneTapStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	h.ServeHTTP(first, oneTapStartRequest(oneTapPromptBody, device))
	previous := first.Result().Cookies()
	if first.Code != http.StatusOK || len(previous) != 1 || p.calls != 1 {
		t.Fatal("first Start did not establish the original browser cookie")
	}
	firstKey := p.last.Key
	p.result.Token, err = session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	p.result.CommandID, err = identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	p.result.FlowID, err = identity.NewPreAuthTransactionID()
	if err != nil {
		t.Fatal(err)
	}
	request := oneTapStartRequest(oneTapPromptBody, device)
	request.Header.Set("Idempotency-Key", "one-tap-deliberate-second-attempt")
	request.AddCookie(previous[0])
	second := httptest.NewRecorder()
	h.ServeHTTP(second, request)
	cookies := second.Result().Cookies()
	if second.Code != http.StatusOK || p.calls != 2 || len(rate.requests) != 2 || p.last.Key == firstKey ||
		len(cookies) != 1 || cookies[0].Name != previous[0].Name || cookies[0].Value == previous[0].Value {
		t.Fatal("a previous flow cookie blocked a fresh keyed Start or was reused as authority", second.Code)
	}
}

func TestOneTapStartRejectsNonfreshOrMalformedNativeOutputWithoutReveal(t *testing.T) {
	for _, mode := range []string{"error", "replayed", "unknown", "not-committed", "conflict", "in-progress", "command", "flow", "client", "origin", "nonce", "zero-nonce", "expired", "overlong-expiry", "cookie-value", "cookie-domain", "cookie-expiry", "cookie-ttl", "cookie-raw", "cookie-unparsed", "cookie-insecure", "cookie-readable", "cookie-name", "cookie-path", "cookie-samesite", "cookie-partitioned", "cookie-quoted", "options", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, device, _ := oneTapStartFixture(t)
			r := oneTapStartRequest(oneTapPromptBody, device)
			switch mode {
			case "error":
				p.err = errors.New("private provider diagnostic")
			case "replayed":
				p.result.Replayed = true
			case "unknown":
				p.result.Outcome = identity.CommitOutcomeUnknown
			case "not-committed":
				p.result.Outcome = identity.CommitOutcomeNotCommitted
			case "conflict":
				p.result.Outcome = identity.CommitOutcomeConflict
			case "in-progress":
				p.result.Outcome = identity.CommitOutcomeInProgress
			case "command":
				p.result.CommandID = ""
			case "flow":
				p.result.FlowID = ""
			case "client":
				p.result.ClientID = "other"
			case "origin":
				p.result.Origin = "https://foreign.example"
			case "nonce":
				p.result.Nonce = "noncanonical"
			case "zero-nonce":
				p.result.Nonce = strings.Repeat("A", 43)
			case "expired":
				p.result.ExpiresAt = c.Now()
			case "overlong-expiry":
				p.result.ExpiresAt = c.Now().Add(time.Hour)
			case "cookie-value":
				p.result.Cookie.Value = "private-secret"
			case "cookie-domain":
				p.result.Cookie.Domain = "app.example"
			case "cookie-expiry":
				p.result.Cookie.Expires = p.result.ExpiresAt.Add(time.Second)
			case "cookie-ttl":
				p.result.Cookie.MaxAge = 301
			case "cookie-raw":
				p.result.Cookie.Raw = "private-secret"
			case "cookie-unparsed":
				p.result.Cookie.Unparsed = []string{"private-secret"}
			case "cookie-insecure":
				p.result.Cookie.Secure = false
			case "cookie-readable":
				p.result.Cookie.HttpOnly = false
			case "cookie-name":
				p.result.Cookie.Name = "other"
			case "cookie-path":
				p.result.Cookie.Path = "/other"
			case "cookie-samesite":
				p.result.Cookie.SameSite = http.SameSiteNoneMode
			case "cookie-partitioned":
				p.result.Cookie.Partitioned = true
			case "cookie-quoted":
				p.result.Cookie.Quoted = true
			case "options":
				prompt, _ := onetap.NewOneTapPromptOptions(onetap.OneTapPromptConfig{Context: onetap.PromptUse, CancelOnTapOutside: true})
				p.result.Options, _ = onetap.NewBrowserStartOptions(prompt, onetap.OneTapButtonOptions{})
			case "cancelled":
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				p.cancel = cancel
			}
			w := serveOneTapStart(t, c, r)
			if w.Code < 400 || p.calls != 1 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "nonce") || strings.Contains(w.Body.String(), "private") {
				t.Fatal("nonfresh result released browser state", mode, w.Code)
			}
			if _, err := p.result.Token.Reveal(); err != nil {
				t.Fatal("rejected result consumed its token")
			}
		})
	}
}

func TestOneTapStartSelectedFeatureDocumentsActualWire(t *testing.T) {
	c, p, _, device, _ := oneTapStartFixture(t)
	feature, err := oauthhttp.NewOneTapStartFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, document, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "One Tap", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(document.JSON(), &wire) != nil || len(wire.Paths) != 1 {
		t.Fatal("feature enabled sibling operations")
	}
	var operation struct {
		RequestBody struct {
			Content map[string]struct {
				Schema map[string]json.RawMessage `json:"schema"`
			} `json:"content"`
		} `json:"requestBody"`
		Responses map[string]json.RawMessage `json:"responses"`
	}
	if json.Unmarshal(wire.Paths["/v1/oauth/onetap-start"]["post"], &operation) != nil || operation.RequestBody.Content["application/json"].Schema["oneOf"] == nil || operation.Responses["200"] == nil {
		t.Fatal("document omitted actual exclusive request or success contract")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, oneTapStartRequest(oneTapPromptBody, device))
	if w.Code != 200 || p.calls != 1 {
		t.Fatal("documented route does not execute selected operation", w.Code)
	}
}

func TestOneTapStartWireCoversActualOuterOriginDenial(t *testing.T) {
	c, p, _, device, _ := oneTapStartFixture(t)
	feature, err := oauthhttp.NewOneTapStartFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration,
		Document: identityhttp.DocumentConfig{Title: "One Tap", Version: "1"}}, feature.Operations(), nil)
	if err != nil {
		t.Fatal(err)
	}
	r := oneTapStartRequest(oneTapPromptBody, device)
	r.Header.Set("Origin", "https://foreign.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || w.Header().Get("Content-Type") != "text/plain; charset=utf-8" || p.calls != 0 || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("router did not emit the expected fixed origin denial before Start", w.Code)
	}
	var published struct {
		Paths map[string]struct {
			Post struct {
				Responses map[string]struct {
					Content map[string]struct {
						Schema struct{ Const string } `json:"schema"`
					} `json:"content"`
				} `json:"responses"`
			} `json:"post"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(doc.JSON(), &published); err != nil {
		t.Fatal(err)
	}
	if got := published.Paths[r.URL.Path].Post.Responses["403"].Content["text/plain"].Schema.Const; got == "" || got != w.Body.String() {
		t.Fatal("published Start wire omits the actual fixed 403 error")
	}
}

func TestOneTapStartDeniesRateOutageAndKnownProviderIPLimit(t *testing.T) {
	c, p, rate, device, _ := oneTapStartFixture(t)
	h, err := oauthhttp.NewOneTapStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	// The boundary double supplies fresh custody for each deliberate call; the
	// rate limiter, not the double, owns the provider/IP admission budget.
	c.Start = func(ctx context.Context, r onetap.BrowserStartRequest) (oauthhttp.OneTapStartHTTPResult, error) {
		out, e := p.start(ctx, r)
		out.Token, _ = session.NewToken(32)
		return out, e
	}
	h, err = oauthhttp.NewOneTapStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 31 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, oneTapStartRequest(oneTapPromptBody, device))
		if i < 30 && w.Code != 200 {
			t.Fatal("provider budget denied early", i, w.Code)
		}
		if i == 30 && (w.Code != 429 || w.Header().Get("Retry-After") != "20" || w.Header().Get("Set-Cookie") != "") {
			t.Fatal("known rate denial lost bounded retry or leaked custody", w.Code)
		}
	}
	if p.calls != 30 {
		t.Fatal("rate denial reached native Start")
	}
	rate.fail = true
	r := oneTapStartRequest(oneTapPromptBody, device)
	r.RemoteAddr = "192.0.2.2:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || p.calls != 30 || w.Header().Get("Retry-After") != "" {
		t.Fatal("rate outage failed open")
	}
}

func TestOneTapStartProtectsResponseCustodyAcrossMiddleware(t *testing.T) {
	for _, phase := range []identityhttp.MiddlewarePhase{identityhttp.MiddlewareBeforeAuth, identityhttp.MiddlewareAfterAuth, identityhttp.MiddlewareBeforeHandler} {
		for _, mode := range []string{"early", "expired", "injected"} {
			t.Run(mode, func(t *testing.T) {
				c, p, _, cookie, device := oneTapStartFixture(t)
				now := c.Now()
				c.Now = func() time.Time { return now }
				h, err := oauthhttp.NewOneTapStartHandler(c)
				if err != nil {
					t.Fatal(err)
				}
				h, err = identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "custody", Phase: phase, Order: 1, Handler: func(next http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						w.Header().Set("Set-Cookie", "injected=credential")
						w.Header().Set("Location", "https://foreign.example")
						w.Header().Set("Authorization", "Bearer injected")
						if mode == "early" {
							w.WriteHeader(202)
						}
						if mode == "expired" {
							now = device.ExpiresAt()
						}
						next.ServeHTTP(w, r)
					})
				}}}})
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, oneTapStartRequest(oneTapPromptBody, cookie))
				if w.Header().Get("Location") != "" || w.Header().Get("Authorization") != "" || strings.Contains(w.Header().Get("Set-Cookie"), "injected") {
					t.Fatal("middleware supplied credential custody")
				}
				if mode == "injected" {
					if w.Code != 200 || p.calls != 1 || len(w.Result().Cookies()) != 1 {
						t.Fatal("safe operation result was lost", w.Code)
					}
				} else if p.calls != 0 || w.Header().Get("Set-Cookie") != "" {
					t.Fatal("closed response or expired device still initiated native flow", mode, w.Code)
				}
			})
		}
	}
}

func TestOneTapStartDoesNotRetryOrRedeliverAfterLostResponse(t *testing.T) {
	c, p, _, cookie, _ := oneTapStartFixture(t)
	h, err := oauthhttp.NewOneTapStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := &oneTapLostWriter{header: make(http.Header)}
	h.ServeHTTP(w, oneTapStartRequest(oneTapPromptBody, cookie))
	if p.calls != 1 || w.writes != 1 {
		t.Fatal("lost acknowledgement retried Start or write")
	}
	second := httptest.NewRecorder()
	h.ServeHTTP(second, oneTapStartRequest(oneTapPromptBody, cookie))
	if p.calls != 2 || second.Code != 503 || second.Header().Get("Set-Cookie") != "" || strings.Contains(second.Body.String(), "nonce") {
		t.Fatal("consumed result redelivered or restarted within a call", second.Code)
	}
}

func TestOneTapStartChecksCustodyAtActualResponseCommit(t *testing.T) {
	for _, mode := range []string{"expiry", "cancel", "status", "body", "remaining-lifetime"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, cookie, _ := oneTapStartFixture(t)
			now := c.Now()
			c.Now = func() time.Time { return now }
			r := oneTapStartRequest(oneTapPromptBody, cookie)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			h, err := oauthhttp.NewOneTapStartHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			h, err = identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "late-custody", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(&oneTapCommitWriter{ResponseWriter: w, write: func(body []byte) (int, error) {
						switch mode {
						case "expiry":
							now = p.result.ExpiresAt
						case "cancel":
							cancel()
						case "status":
							w.WriteHeader(202)
						case "body":
							body = []byte(`{"injected":"body"}`)
						case "remaining-lifetime":
							now = p.result.ExpiresAt.Add(-3 * time.Second)
						}
						return w.Write(body)
					}}, r)
				})
			}}}})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if mode == "remaining-lifetime" {
				cookies := w.Result().Cookies()
				if w.Code != 200 || len(cookies) != 1 || cookies[0].MaxAge != 3 || !cookies[0].Expires.Equal(p.result.ExpiresAt) {
					t.Fatal("response renewed the original lifetime", w.Code)
				}
				return
			}
			if w.Code != 503 || p.calls != 1 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "nonce") {
				t.Fatal("late response change disclosed browser custody", mode, w.Code)
			}
			if _, err := p.result.Token.Reveal(); err != nil {
				t.Fatal("rejected late response consumed native custody")
			}
		})
	}
}

type oneTapCommitWriter struct {
	http.ResponseWriter
	write func([]byte) (int, error)
}

func (w *oneTapCommitWriter) Write(body []byte) (int, error) { return w.write(body) }

type oneTapLostWriter struct {
	header http.Header
	writes int
}

func (w *oneTapLostWriter) Header() http.Header       { return w.header }
func (*oneTapLostWriter) WriteHeader(int)             {}
func (w *oneTapLostWriter) Write([]byte) (int, error) { w.writes++; return 0, io.ErrClosedPipe }

func TestOneTapStartRejectsIncompleteComposition(t *testing.T) {
	for _, alter := range []func(*oauthhttp.OneTapStartConfig){
		func(c *oauthhttp.OneTapStartConfig) { c.Start = nil }, func(c *oauthhttp.OneTapStartConfig) { c.Rate = nil }, func(c *oauthhttp.OneTapStartConfig) { c.Now = nil }, func(c *oauthhttp.OneTapStartConfig) { c.MaximumDuration = 0 }, func(c *oauthhttp.OneTapStartConfig) { c.MaximumDuration = 31 * time.Second }, func(c *oauthhttp.OneTapStartConfig) { c.ProviderID = "" }, func(c *oauthhttp.OneTapStartConfig) { c.ClientID = "" }, func(c *oauthhttp.OneTapStartConfig) { c.Lifetime = session.LifetimeConfig{} }, func(c *oauthhttp.OneTapStartConfig) {
			c.FlowCookie, _ = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-other", SameSite: http.SameSiteLaxMode})
		}, func(c *oauthhttp.OneTapStartConfig) {
			c.Device.Cookie, _ = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteStrictMode})
		},
	} {
		c, _, _, _, _ := oneTapStartFixture(t)
		alter(&c)
		if h, err := oauthhttp.NewOneTapStartHandler(c); h != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("incomplete composition enabled")
		}
	}
}

func FuzzOneTapStartClosedInput(f *testing.F) {
	f.Add(oneTapPromptBody)
	f.Add(oneTapButtonBody)
	f.Add(`{"prompt":null}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 32768 {
			t.Skip()
		}
		c, p, _, cookie, _ := oneTapStartFixture(t)
		w := serveOneTapStart(t, c, oneTapStartRequest(body, cookie))
		if p.calls > 1 || w.Header().Get("Location") != "" {
			t.Fatal("input caused retry or redirect")
		}
		if p.calls == 1 {
			if _, err := onetap.NewBrowserStartRequest(p.last); err != nil {
				t.Fatal("invalid input reached native port")
			}
		}
		if w.Code != 200 && (w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "nonce")) {
			t.Fatal("invalid input received browser custody")
		}
	})
}
