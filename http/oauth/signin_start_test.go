package oauthhttp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// This double occupies only the native initiation boundary. It cannot issue
// state or authenticate browser intent; native integration proves those effects.
type signinStartProbe struct {
	calls   int
	last    oauth.SigninStartRequest
	result  oauth.SigninStartResult
	err     error
	bounded bool
	cancel  context.CancelFunc
}

func (p *signinStartProbe) SigninStart(ctx context.Context, r oauth.SigninStartRequest) (oauth.SigninStartResult, error) {
	p.calls++
	p.last = r
	_, p.bounded = ctx.Deadline()
	if p.cancel != nil {
		p.cancel()
	}
	return p.result, p.err
}

type signinStartRate struct {
	localStrict
	requests []ratelimit.Request
	fail     bool
}

func (s *signinStartRate) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	s.requests = append(s.requests, r)
	if s.fail {
		return ratelimit.Decision{}, ratelimit.UnknownOutcome(nil)
	}
	return s.localStrict.AdmitStrict(ctx, r)
}

const signinStartBody = `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","provider":"configured","callback":"https://app.example/complete","errorCallback":"https://app.example/failed","scopes":["openid"],"signupDisabled":true}`

func signinStartFixture(t *testing.T) (oauthhttp.SigninStartConfig, *signinStartProbe, *signinStartRate, *http.Cookie, session.BrowserDevice) {
	t.Helper()
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	store, err := memory.New(memory.Options{MaxKeys: 256, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	backend := &signinStartRate{localStrict: localStrict{store}}
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: "signin-start-test", IdentifierKey: [32]byte{1}, Now: func() time.Time { return now }, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	flow, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	key, _ := session.NewBrowserDeviceKey(1, []byte(strings.Repeat("d", 32)))
	deviceConfig := session.BrowserDeviceConfig{Namespace: "signin-http", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	devices, err := session.NewBrowserDeviceCodec(deviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	device, err := devices.Issue(t.Context(), now, "tenant", "https://app.example")
	if err != nil {
		t.Fatal(err)
	}
	issued := &http.Response{Header: http.Header{"Set-Cookie": {device.CookieHeader()}}}
	profile := oauth.ProviderProfile{ID: "configured", Version: 1, Issuer: "https://issuer.example", ClientID: "client", AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: "https://issuer.example/token", RedirectURI: "https://app.example/v1/oauth/callback", ClientAuthentication: oauth.PublicClient, Scopes: []string{"openid"}, Algorithms: []string{"ES256"}, ResponseMode: "query", PKCEMethod: "S256", NonceRequired: true, StateBytes: 32, NonceBytes: 32, Timeout: time.Second, ClockSkew: time.Minute, MaxResponseBytes: 65536, MaxTokenBytes: 16384, MaxCodeBytes: 4096}
	query := url.Values{"response_type": {"code"}, "response_mode": {"query"}, "client_id": {profile.ClientID}, "redirect_uri": {profile.RedirectURI}, "scope": {"openid"}, "state": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, "nonce": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, "code_challenge": {base64.RawURLEncoding.EncodeToString(make([]byte, 32))}, "code_challenge_method": {"S256"}}
	redirect, _ := url.Parse(profile.AuthorizationEndpoint + "?" + query.Encode())
	probe := &signinStartProbe{result: oauth.SigninStartResult{RedirectURI: *redirect, TransactionID: "AQEBAQEBAQEBAQEBAQEBAQ", ExpiresAt: now.Add(5 * time.Minute)}}
	config := oauthhttp.SigninStartConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 16384, MaximumURLBytes: 8192, MaximumBodyBytes: 16384, MaximumDecodedBytes: 16384, MaximumFields: 32, MaximumDepth: 8}, MaximumForwardedHops: 8, TenantHosts: []identityhttp.TenantHost{{Host: "app.example", TenantID: "tenant"}}}, Provider: profile, Start: probe, Rate: rate, FlowCookie: flow, Device: deviceConfig, Origin: "https://app.example", CallbackAllowlist: []string{"https://app.example/complete", "https://app.example/failed"}, Lifetime: session.LifetimeConfig{Default: session.PersistentSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}, ActorID: "public-login", PolicyRevision: 1, Now: func() time.Time { return now }, MaximumDuration: time.Second}
	return config, probe, backend, issued.Cookies()[0], device
}

func signinStartRequest(body string, device *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://app.example/v1/oauth/signin-start", strings.NewReader(body))
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "[::ffff:192.0.2.1]:1234"
	r.Header.Set("Origin", "https://app.example")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "Original-Key_123")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
	r.AddCookie(device)
	return r
}

func serveSigninStart(t *testing.T, c oauthhttp.SigninStartConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := oauthhttp.NewSigninStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestSigninStartBindsOriginalAnonymousFlowAndTrustedBrowser(t *testing.T) {
	for _, choice := range []struct {
		name, suffix string
		expected     session.RememberChoice
	}{{"omitted", "", session.PersistentSession}, {"browser", `,"remember":false`, session.BrowserSession}, {"persistent", `,"remember":true`, session.PersistentSession}} {
		t.Run(choice.name, func(t *testing.T) {
			c, p, rate, cookie, device := signinStartFixture(t)
			body := strings.TrimSuffix(signinStartBody, "}") + choice.suffix + "}"
			request := signinStartRequest(body, cookie)
			request.Header.Set("Forwarded", "for=198.51.100.2;proto=https;host=foreign.example")
			w := serveSigninStart(t, c, request)
			if w.Code != 200 || p.calls != 1 || !p.bounded || len(rate.requests) != 1 {
				t.Fatal("original initiation was not bounded and admitted exactly once", w.Code)
			}
			r := p.last
			key, _ := identity.NewIdempotencyKey([]byte("Original-Key_123"))
			keyDigest, _ := key.Digest([32]byte{1})
			actualDigest, keyErr := r.IdempotencyKey.Digest([32]byte{1})
			if r.Validate() != nil || r.FlowID != "AQEBAQEBAQEBAQEBAQEBAQ" || r.FlowCookie.Token() != strings.Repeat("A", 43) || keyErr != nil || actualDigest != keyDigest || r.Network != "192.0.2.1" || r.Device != device.DeviceID() || r.Origin != string(c.Origin) || r.TenantID != "tenant" || r.Remember.Choice() != choice.expected {
				t.Fatal("original intent or trusted attribution changed")
			}
			caller := r.Caller
			if caller.Request.Subject.Kind != authorization.SubjectServiceAccount || caller.Request.Subject.ID != "public-login" || caller.Request.Resource.Type != "identity.anonymous-flow" || string(caller.Request.Resource.ID) != string(r.FlowID) || caller.Request.Action != "identity.oauth.signin-start" {
				t.Fatal("caller was not the configured service acting on the original flow")
			}
			var out map[string]json.RawMessage
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 3 || out["redirectURI"] == nil || out["transactionID"] == nil || out["expiresAt"] == nil || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("response did not remain an explicit noncredential projection")
			}
		})
	}
}

func TestSigninStartRejectsMalformedOrUnsupportedIntentBeforeNativeAdmission(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*http.Request)
	}{
		{"missing-key", func(r *http.Request) { r.Header.Del("Idempotency-Key") }},
		{"duplicate-key", func(r *http.Request) { r.Header.Add("Idempotency-Key", "another") }},
		{"alias-key", func(r *http.Request) { r.Header["idempotency-key"] = []string{"another"} }},
		{"folded-key", func(r *http.Request) { r.Header.Set("Idempotency-Key", "one,two") }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "mode=popup"; r.RequestURI = r.URL.RequestURI() }},
		{"authorization", func(r *http.Request) { r.Header.Set("Authorization", "Bearer unrelated") }},
		{"csrf-alternative", func(r *http.Request) { r.Header.Set("X-CSRF-Token", "alternative") }},
		{"missing-origin", func(r *http.Request) { r.Header.Del("Origin") }},
		{"foreign-origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }},
		{"duplicate-origin", func(r *http.Request) { r.Header.Add("Origin", "https://app.example") }},
		{"foreign-host", func(r *http.Request) { r.Host = "foreign.example" }},
		{"plaintext", func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" }},
		{"missing-cookie", func(r *http.Request) { r.Header.Del("Cookie") }},
		{"duplicate-flow", func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
		}},
		{"duplicate-device", func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "__Host-identity_device", Value: "invalid"}) }},
		{"forged-device", func(r *http.Request) {
			r.Header.Set("Cookie", "__Host-identity_flow="+strings.Repeat("A", 43)+"; __Host-identity_device="+strings.Repeat("A", 114))
		}},
		{"trailer", func(r *http.Request) { r.Trailer = http.Header{"Idempotency-Key": {"alternative"}} }},
		{"wrong-method", func(r *http.Request) { r.Method = http.MethodGet }},
		{"wrong-path", func(r *http.Request) { r.URL.Path += "/"; r.RequestURI = r.URL.RequestURI() }},
		{"content-type", func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }},
		{"encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
	}
	for _, body := range []string{
		strings.Replace(signinStartBody, `"signupDisabled":true`, `"signupDisabled":false`, 1),
		strings.Replace(signinStartBody, `"provider":"configured"`, `"provider":"foreign"`, 1),
		strings.Replace(signinStartBody, `"scopes":["openid"]`, `"scopes":["openid","email"]`, 1),
		strings.Replace(signinStartBody, `https://app.example/complete`, `https://foreign.example/complete`, 1),
		strings.Replace(signinStartBody, `"flowID":"AQEBAQEBAQEBAQEBAQEBAQ"`, `"flowID":null`, 1),
		strings.TrimSuffix(signinStartBody, "}") + `,"remember":null}`,
		strings.TrimSuffix(signinStartBody, "}") + `,"remember":"true"}`,
		strings.TrimSuffix(signinStartBody, "}") + `,"provider":"configured"}`,
		strings.TrimSuffix(signinStartBody, "}") + `,"Provider":"configured"}`,
		strings.TrimSuffix(signinStartBody, "}") + `,"device":"client-chosen"}`,
		strings.TrimSuffix(signinStartBody, "}") + `,"idempotencyKey":"body-alternative"}`,
		strings.TrimSuffix(signinStartBody, "}") + `,"mode":"popup"}`,
		signinStartBody + `{}`,
		strings.Repeat(" ", 16384) + signinStartBody,
	} {
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
			c, p, rate, device, _ := signinStartFixture(t)
			r := signinStartRequest(signinStartBody, device)
			tc.alter(r)
			w := serveSigninStart(t, c, r)
			if w.Code < 400 || p.calls != 0 || len(rate.requests) != 0 || w.Header().Get("Set-Cookie") != "" || strings.Contains(w.Body.String(), "Original-Key") || strings.Contains(w.Body.String(), "redirectURI") {
				t.Fatal("invalid browser intent reached native initiation or leaked custody", w.Code)
			}
		})
	}
}

func TestSigninStartProviderIPBudgetDeniesAndReportsRetry(t *testing.T) {
	c, p, rate, device, _ := signinStartFixture(t)
	h, err := oauthhttp.NewSigninStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 31 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, signinStartRequest(signinStartBody, device))
		if i < 30 && w.Code != 200 {
			t.Fatal("provider budget denied early", i, w.Code)
		}
		if i == 30 && (w.Code != 429 || w.Header().Get("Retry-After") != "20" || strings.Contains(w.Body.String(), "redirectURI")) {
			t.Fatal("provider denial lost stable retry metadata", w.Code)
		}
	}
	if p.calls != 30 || len(rate.requests) != 31 {
		t.Fatal("provider denial reached native initiation")
	}
	rate.fail = true
	w := httptest.NewRecorder()
	r := signinStartRequest(signinStartBody, device)
	r.RemoteAddr = "192.0.2.2:1234"
	h.ServeHTTP(w, r)
	if w.Code != 503 || p.calls != 30 || w.Header().Get("Retry-After") != "" {
		t.Fatal("provider rate outage failed open or fabricated retry", w.Code)
	}
}

func TestSigninStartNeverProjectsFailureOrMalformedNativeResult(t *testing.T) {
	for _, mode := range []string{"error", "denied", "conflict", "expired", "empty-transaction", "foreign-redirect", "userinfo", "fragment", "opaque", "oversized", "wrong-client", "credential-field", "duplicate-state", "missing-query", "unencodable-expiry", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			c, p, _, device, _ := signinStartFixture(t)
			r := signinStartRequest(signinStartBody, device)
			status := 503
			switch mode {
			case "error":
				p.err = errors.New("private diagnostic must not escape")
			case "denied":
				p.err = identity.ForbiddenError{}
				status = 403
			case "conflict":
				p.err = identity.ConflictError{}
				status = 409
			case "expired":
				p.result.ExpiresAt = c.Now()
			case "empty-transaction":
				p.result.TransactionID = ""
			case "foreign-redirect":
				p.result.RedirectURI.Host = "foreign.example"
			case "userinfo":
				p.result.RedirectURI.User = url.UserPassword("private", "secret")
			case "fragment":
				p.result.RedirectURI.Fragment = "private-secret"
			case "opaque":
				p.result.RedirectURI.Opaque = "private-secret"
			case "oversized":
				p.result.RedirectURI.RawQuery += strings.Repeat("x", 16384)
			case "wrong-client":
				q := p.result.RedirectURI.Query()
				q.Set("client_id", "foreign")
				p.result.RedirectURI.RawQuery = q.Encode()
			case "credential-field":
				p.result.RedirectURI.RawQuery += "&access_token=private-secret"
			case "duplicate-state":
				p.result.RedirectURI.RawQuery += "&state=another-state"
			case "missing-query":
				p.result.RedirectURI.RawQuery = ""
			case "unencodable-expiry":
				p.result.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			case "cancelled":
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				p.cancel = cancel
			}
			w := serveSigninStart(t, c, r)
			if w.Code != status || p.calls != 1 || strings.Contains(w.Body.String(), "redirectURI") || strings.Contains(w.Body.String(), "private") || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" {
				t.Fatal("native failure or unsafe output disclosed redirect state", w.Code)
			}
		})
	}
}

func TestSigninStartCannotRenewDeviceAcrossMiddleware(t *testing.T) {
	for _, phase := range []identityhttp.MiddlewarePhase{identityhttp.MiddlewareBeforeAuth, identityhttp.MiddlewareAfterAuth, identityhttp.MiddlewareBeforeHandler} {
		c, p, _, deviceCookie, device := signinStartFixture(t)
		now := c.Now()
		c.Now = func() time.Time { return now }
		h, err := oauthhttp.NewSigninStartHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		h, err = identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/reference", Middleware: identityhttp.Middleware{Name: "advance-clock", Phase: phase, Order: 1, Handler: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { now = device.ExpiresAt(); next.ServeHTTP(w, r) })
		}}}})
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, signinStartRequest(signinStartBody, deviceCookie))
		if w.Code != 503 || p.calls != 0 || strings.Contains(w.Body.String(), "redirectURI") {
			t.Fatal("expired original device reached native initiation", phase, w.Code)
		}
	}
}

func TestSigninStartFreezesConfigurationAndHonorsCanceledRequests(t *testing.T) {
	c, p, _, device, _ := signinStartFixture(t)
	h, err := oauthhttp.NewSigninStartHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	c.Provider.Scopes[0], c.CallbackAllowlist[0] = "email", "https://foreign.example/complete"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinStartRequest(signinStartBody, device))
	if w.Code != 200 || p.calls != 1 {
		t.Fatal("caller mutation replaced frozen configuration", w.Code)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, signinStartRequest(signinStartBody, device).WithContext(ctx))
	if w.Code != 503 || p.calls != 1 {
		t.Fatal("canceled request reached native initiation", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, nil)
	if w.Code != 400 || p.calls != 1 {
		t.Fatal("nil request reached native initiation", w.Code)
	}
}

func FuzzSigninStartClosedBody(f *testing.F) {
	f.Add(signinStartBody)
	f.Add(`{"flowID":null}`)
	f.Add(strings.TrimSuffix(signinStartBody, "}") + `,"mode":"popup"}`)
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 32768 {
			t.Skip()
		}
		c, p, _, device, _ := signinStartFixture(t)
		w := serveSigninStart(t, c, signinStartRequest(body, device))
		if p.calls > 1 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" {
			t.Fatal("body parsing duplicated initiation or minted credentials")
		}
		if p.calls == 1 && p.last.Validate() != nil {
			t.Fatal("invalid browser intent reached native initiation")
		}
		if w.Code != 200 && strings.Contains(w.Body.String(), "redirectURI") {
			t.Fatal("rejected body received native state")
		}
	})
}

func TestSigninStartRejectsIncompleteOrUnsupportedComposition(t *testing.T) {
	for _, change := range []func(*oauthhttp.SigninStartConfig){
		func(c *oauthhttp.SigninStartConfig) { c.Start = nil },
		func(c *oauthhttp.SigninStartConfig) { var p *signinStartProbe; c.Start = p },
		func(c *oauthhttp.SigninStartConfig) { c.Rate = nil },
		func(c *oauthhttp.SigninStartConfig) { c.Now = nil },
		func(c *oauthhttp.SigninStartConfig) { c.ActorID = "" },
		func(c *oauthhttp.SigninStartConfig) { c.PolicyRevision = 0 },
		func(c *oauthhttp.SigninStartConfig) { c.MaximumDuration = 31 * time.Second },
		func(c *oauthhttp.SigninStartConfig) { c.Provider.ResponseMode = "form_post" },
		func(c *oauthhttp.SigninStartConfig) {
			c.Provider.RedirectURI = "https://foreign.example/v1/oauth/callback"
		},
		func(c *oauthhttp.SigninStartConfig) { c.CallbackAllowlist = nil },
		func(c *oauthhttp.SigninStartConfig) { c.CallbackAllowlist = []string{"http://app.example/complete"} },
		func(c *oauthhttp.SigninStartConfig) { c.CallbackAllowlist[1] = "http://app.example/failed" },
		func(c *oauthhttp.SigninStartConfig) { c.CallbackAllowlist[1] = c.CallbackAllowlist[0] },
		func(c *oauthhttp.SigninStartConfig) { c.Provider.AuthorizationEndpoint += "?custom=unsupported" },
		func(c *oauthhttp.SigninStartConfig) { c.Lifetime = session.LifetimeConfig{} },
		func(c *oauthhttp.SigninStartConfig) {
			c.FlowCookie, _ = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteStrictMode})
		},
		func(c *oauthhttp.SigninStartConfig) {
			c.Device.Cookie, _ = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteStrictMode})
		},
	} {
		c, _, _, _, _ := signinStartFixture(t)
		change(&c)
		if h, err := oauthhttp.NewSigninStartHandler(c); h != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("unsupported signin composition enabled")
		}
	}
}
