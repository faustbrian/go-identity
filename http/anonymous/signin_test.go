package anonymoushttp_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/anonymous"
	identityhttp "github.com/faustbrian/go-identity/http"
	anonymoushttp "github.com/faustbrian/go-identity/http/anonymous"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

type shared struct{ *memory.Store }

func (*shared) Name() string { return "http-guest-test" }
func (s *shared) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return s.Store.AdmitStrict(ctx, r)
}

// The double is only the native workflow port. Rate counting, device custody,
// network/origin decoding and request parsing are real public owners. Separate
// reference PostgreSQL tests must prove the durable journey, not this double.
type signinOwner struct {
	anonymous.Issuer
	reads, calls int
	request      anonymous.SigninRequest
	result       *anonymous.SigninResult
	err          error
	onSignin     func(context.Context)
}

func (s *signinOwner) SigninRateSource(ctx context.Context, r anonymous.SigninRequest) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded source")
	}
	s.reads++
	return "authenticated-native-original-flow", nil
}
func (s *signinOwner) Signin(ctx context.Context, r anonymous.SigninRequest) (anonymous.SigninResult, error) {
	if _, ok := ctx.Deadline(); !ok || r.Validate() != nil {
		panic("invalid native invocation")
	}
	s.calls++
	s.request = r
	if s.onSignin != nil {
		s.onSignin(ctx)
	}
	if s.result != nil {
		return *s.result, s.err
	}
	return anonymous.SigninResult{Outcome: identity.CommitOutcomeNotCommitted}, identity.ForbiddenError{}
}

func signinFixture(t *testing.T) (anonymoushttp.SigninConfig, *signinOwner, func() *http.Request) {
	t.Helper()
	now := time.Now().UTC()
	store, err := memory.New(memory.Options{MaxKeys: 128, Shards: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: &shared{store}, Namespace: "guest-entry", IdentifierKey: [32]byte{1}, Now: func() time.Time { return now }, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	flow, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	guest, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_guest", SameSite: http.SameSiteLaxMode})
	deviceCookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteLaxMode})
	key, _ := session.NewBrowserDeviceKey(1, []byte(strings.Repeat("x", 32)))
	devices := session.BrowserDeviceConfig{Namespace: "guest-http", Keys: []session.BrowserDeviceKey{key}, ActiveVersion: 1, Lifetime: time.Hour, Cookie: deviceCookie}
	codec, err := session.NewBrowserDeviceCodec(devices)
	if err != nil {
		t.Fatal(err)
	}
	device, err := codec.Issue(t.Context(), now, "tenant-a", "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	response := &http.Response{Header: http.Header{"Set-Cookie": []string{device.CookieHeader()}}}
	if len(response.Cookies()) != 1 {
		t.Fatal("device fixture")
	}
	owner := &signinOwner{}
	c := anonymoushttp.SigninConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Service: owner, Rate: rate, Origin: "https://tenant.example", FlowCookie: flow, SessionCookie: guest, Device: devices, ActorID: "public-ingress", PolicyRevision: 1, Audience: "guest-service", Now: func() time.Time { return now }, MaximumDuration: 2 * time.Second, Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}}
	token, _ := session.NewToken(32)
	wire, _ := token.Reveal()
	return c, owner, func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/v1/anonymous/signin", strings.NewReader(`{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","callbackURL":""}`))
		r.Host = "tenant.example"
		r.RemoteAddr = "198.51.100.7:1234"
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", string(c.Origin))
		r.Header.Set("Idempotency-Key", "original-guest-attempt")
		r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: wire})
		r.AddCookie(response.Cookies()[0])
		return r
	}
}

func TestSigninRequiresOriginalKeyAndClosedBrowserCustody(t *testing.T) {
	for _, mode := range []string{"valid", "missing-key", "duplicate-key", "body-key", "body-subject", "wrong-origin", "foreign-host", "authorization", "duplicate-flow", "missing-device", "query", "wrong-method"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, request := signinFixture(t)
			r := request()
			want := 400
			switch mode {
			case "valid":
				want = 403
			case "missing-key":
				r.Header.Del("Idempotency-Key")
			case "duplicate-key":
				r.Header.Add("Idempotency-Key", "original-guest-attempt")
			case "body-key":
				r = replaceBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","callbackURL":"","idempotencyKey":"x"}`)
			case "body-subject":
				r = replaceBody(r, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","callbackURL":"","userID":"selected"}`)
			case "wrong-origin":
				r.Header.Set("Origin", "https://other.example")
				want = 403
			case "foreign-host":
				r.Host = "other.example"
				want = 421
			case "authorization":
				r.Header.Set("Authorization", "Bearer "+auth.NewBearerCredential("forbidden").Token())
			case "duplicate-flow":
				r.AddCookie(r.Cookies()[0])
			case "missing-device":
				r.Header.Set("Cookie", r.Cookies()[0].String())
			case "query":
				r.URL.RawQuery = "userID=selected"
			case "wrong-method":
				r.Method = http.MethodGet
				want = 405
			}
			h, err := anonymoushttp.NewSigninHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("wrong bounded signin response: status=%d", w.Code)
			}
			if mode == "valid" {
				if owner.calls != 1 || owner.reads != 1 || string(owner.request.Caller.Request.Subject.ID) != string(c.ActorID) || owner.request.IdempotencyKey == (identity.IdempotencyKey{}) {
					t.Fatal("actual native request lost original key/flow/trusted ingress")
				}
			} else if owner.calls != 0 || owner.reads != 0 {
				t.Fatal("invalid request reached native work")
			}
		})
	}
}

func replaceBody(r *http.Request, body string) *http.Request {
	next := httptest.NewRequest(r.Method, r.URL.String(), strings.NewReader(body))
	next.Host, next.RemoteAddr, next.TLS, next.Header = r.Host, r.RemoteAddr, r.TLS, r.Header.Clone()
	return next
}

func TestSigninHistoricalOutcomesNeverRedeliverGuestCredentials(t *testing.T) {
	for _, mode := range []string{"replay", "unknown", "committed-error", "conflict", "in-progress"} {
		t.Run(mode, func(t *testing.T) {
			c, owner, request := signinFixture(t)
			r := request()
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			recovery, err := anonymous.NewSigninRecovery(identity.RecoveryQuery{CommandID: id, TenantID: "tenant-a", AnonymousFlowID: "AQEBAQEBAQEBAQEBAQEBAQ", ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.anonymous.signin"}, "AQEBAQEBAQEBAQEBAQEBAQ")
			if err != nil {
				t.Fatal(err)
			}
			owner.result = &anonymous.SigninResult{Outcome: identity.CommitOutcomeCommitted, Recovery: recovery, Replayed: true}
			want := 200
			switch mode {
			case "unknown":
				owner.result.Outcome = identity.CommitOutcomeUnknown
				owner.err = identity.UnknownCommitError{CommandID: id}
				want = 503
			case "committed-error":
				owner.err = identity.UnavailableError{}
				want = 503
			case "conflict":
				owner.result.Outcome = identity.CommitOutcomeConflict
				owner.err = identity.ConflictError{}
				want = 409
			case "in-progress":
				owner.result.Outcome = identity.CommitOutcomeInProgress
				owner.err = identity.InProgressError{RetryAfter: time.Second}
				want = 409
			}
			h, err := anonymoushttp.NewSigninHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			var out anonymoushttp.SigninResponse
			if w.Code != want || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.SignedIn || out.CommandID != id || out.Recovery == nil || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || owner.calls != 1 {
				t.Fatalf("original outcome/custody lost: status=%d", w.Code)
			}
			if mode == "in-progress" && w.Header().Get("Retry-After") != "1" {
				t.Fatal("original busy outcome lost retry metadata")
			}
		})
	}
}

// Native issuance is deliberately doubled only at its owned transport port.
// The record, cookie policy, remember policy and reveal-once custody are real.
func freshGuestResult(t *testing.T, c anonymoushttp.SigninConfig) anonymous.SigninResult {
	t.Helper()
	now := c.Now()
	remember, err := session.ResolveRememberPolicy(session.RememberDefault, c.Lifetime)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{
		Global:        session.AuthorityBinding{ScopeKey: "global", Version: 1},
		Tenant:        session.AuthorityBinding{ScopeKey: "tenant", Version: 1},
		User:          session.AuthorityBinding{ScopeKey: "user", Version: 1},
		Identifier:    session.AuthorityBinding{ScopeKey: "identifier", Version: 1},
		Credential:    session.AuthorityBinding{ScopeKey: "credential", Version: 1},
		SessionFamily: session.AuthorityBinding{ScopeKey: "family", Version: 1},
		Session:       session.AuthorityBinding{ScopeKey: "session", Version: 1},
		Authorization: session.AuthorityBinding{ScopeKey: "authorization", Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := token.Digest(key, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	csrfKey, err := session.NewCSRFKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	csrfState, err := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: "tenant-a", SessionID: "guest-session", SessionVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithCSRF(session.SessionSpec{SessionID: "guest-session", FamilyID: "guest-family", TenantID: "tenant-a", UserID: "guest-user", Audience: c.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationAnonymous, AnonymousAt: now}, IssuedAt: now, LastActivityAt: now}, csrfState)
	if err != nil {
		t.Fatal(err)
	}
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := anonymous.NewSigninRecovery(identity.RecoveryQuery{CommandID: id, TenantID: "tenant-a", AnonymousFlowID: "AQEBAQEBAQEBAQEBAQEBAQ", ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.anonymous.signin"}, "AQEBAQEBAQEBAQEBAQEBAQ")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := c.SessionCookie.Attributes(remember, now, now.Add(remember.AbsoluteTTL()))
	if err != nil {
		t.Fatal(err)
	}
	return anonymous.SigninResult{Outcome: identity.CommitOutcomeCommitted, Recovery: recovery, Session: session.IssueResult{CommandID: id, CommitOutcome: identity.CommitOutcomeCommitted, Session: record, Token: token, Cookie: cookie}, CSRFToken: csrf}
}

func TestSigninFreshDeliveryAndOriginalExpiryAtResponseCommit(t *testing.T) {
	for _, elapsed := range []time.Duration{0, 20*time.Second - time.Nanosecond, 20 * time.Second, 20*time.Second + time.Nanosecond} {
		t.Run(elapsed.String(), func(t *testing.T) {
			c, owner, request := signinFixture(t)
			result := freshGuestResult(t, c)
			owner.result = &result
			original := c.Now()
			// Only the original admission budget expires at this boundary.
			// Device/session remain live, so they cannot mask a missing20s check.
			if _, err := result.Session.Session.Lifetime(original.Add(elapsed)); err != nil {
				t.Fatal("session fixture expired before admission boundary", err)
			}
			requireBrowserDeviceLiveAt(t, c.Device, request(), original.Add(elapsed))
			returned, reads := false, 0
			owner.onSignin = func(context.Context) { returned = true }
			c.Now = func() time.Time {
				if returned {
					reads++
					if reads > 1 {
						return original.Add(elapsed)
					}
				}
				return original
			}
			h, err := anonymoushttp.NewSigninHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, request())
			var out anonymoushttp.SigninResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommandID == "" || out.CommitOutcome != "committed" {
				t.Fatal("original acknowledged history lost")
			}
			if elapsed >= 20*time.Second {
				if w.Code != 503 || out.SignedIn || out.Error != "unavailable" || len(w.Result().Cookies()) != 0 || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatalf("expired response commitment delivered success: status=%d", w.Code)
				}
			} else {
				cookies := w.Result().Cookies()
				if w.Code != 200 || !out.SignedIn || len(cookies) != 1 || cookies[0].Name != "__Host-identity_guest" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].MaxAge != 0 || !cookies[0].Expires.IsZero() {
					t.Fatalf("fresh issuance was not delivered: status=%d", w.Code)
				}
				if _, err := session.ParseToken(cookies[0].Value); err != nil {
					t.Fatal("invalid guest bearer")
				}
				if _, err := session.ParseCSRFToken(w.Header().Get("X-CSRF-Token")); err != nil {
					t.Fatal("missing guest synchronizer")
				}
			}
			if _, err := result.Session.Token.Reveal(); err == nil {
				t.Fatal("original bearer custody remained reusable")
			}
		})
	}
}

func requireBrowserDeviceLiveAt(t *testing.T, config session.BrowserDeviceConfig, r *http.Request, now time.Time) {
	t.Helper()
	codec, err := session.NewBrowserDeviceCodec(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, cookie := range r.Cookies() {
		if cookie.Name == "__Host-identity_device" {
			device, err := codec.Resolve(t.Context(), now, "tenant-a", r.Header.Get("Origin"), cookie.Value)
			if err != nil || !now.Before(device.ExpiresAt()) {
				t.Fatal("device fixture masks original evidence expiry")
			}
			return
		}
	}
	t.Fatal("signed device fixture absent")
}

func TestSigninExposesRealOperationMiddlewareBinding(t *testing.T) {
	c, owner, request := signinFixture(t)
	h, err := anonymoushttp.NewSigninHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := identityhttp.WithOperationMiddleware(h, []identityhttp.MiddlewareDescriptor{{Owner: "identity/anonymous", Middleware: identityhttp.Middleware{Name: "deny-before-owner", Phase: identityhttp.MiddlewareBeforeAuth, Order: 1, Handler: func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(418) })
	}}}})
	if err != nil {
		t.Fatal("anonymous signin has no real middleware phase binding", err)
	}
	w := httptest.NewRecorder()
	bound.ServeHTTP(w, request())
	if w.Code != 418 || owner.calls != 0 || owner.reads != 0 {
		t.Fatal("before-auth middleware did not enclose the actual native stage")
	}
}
