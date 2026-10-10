package passwordhttp_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// Transport plan: original pre-auth cookie and signed device, exact HTTPS
// tenant/origin/callback/remember, IP-before-native-source then identifier rate,
// one native call, raw password destruction, fresh-only cookie/CSRF delivery,
// original metadata on ambiguity and no middleware credential manufacture.
// Actual SQL effects are proven separately through the native composition.
func TestSigninRejectsMissingComposition(t *testing.T) {
	if h, err := passwordhttp.NewSigninHandler(passwordhttp.SigninConfig{}); h != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("unconfigured signin handler accepted")
	}
}

func TestSigninSharedRateOutagePreservesClassification(t *testing.T) {
	f, c, work, device := newSignin(t)
	f.rate.fail = true
	w := serveSignin(t, c, signinRequest(f, device))
	var out passwordhttp.SigninResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Error != "rate_limiter_unavailable" || work.reads != 0 || work.calls != 0 {
		t.Fatal("shared signin rate outage classification lost")
	}
}

// This double occupies the native workflow boundary, not SQL or hashing.
type signinWork struct {
	base           *changeFixture
	calls, reads   int
	last           password.SigninRequest
	canonical      string
	err, sourceErr error
	cancel         context.CancelFunc
	result         password.SigninResult
}

type signinShared struct {
	*atomicOwner
	store *memory.Store
}

func (s *signinShared) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	s.calls++
	if s.fail {
		return ratelimit.Decision{}, ratelimit.UnknownOutcome(nil)
	}
	return s.store.AdmitStrict(ctx, r)
}

func (w *signinWork) SigninRateSource(ctx context.Context, r password.SigninRequest) (string, error) {
	w.reads++
	w.last = r
	if _, ok := ctx.Deadline(); !ok || w.base.rate.calls != 1 {
		panic("source before IP or unbounded")
	}
	return w.canonical, w.sourceErr
}
func (w *signinWork) Signin(ctx context.Context, r password.SigninRequest) (password.SigninResult, error) {
	w.calls++
	w.last = r
	if _, ok := ctx.Deadline(); !ok || w.base.rate.calls != 2 {
		panic("unadmitted signin")
	}
	if w.cancel != nil {
		w.cancel()
	}
	return w.result, w.err
}
func (*signinWork) RecoverSignin(context.Context, password.SigninRecoveryRequest) (password.SigninResult, error) {
	panic("transport retried/recovered")
}

func newSignin(t *testing.T) (*changeFixture, passwordhttp.SigninConfig, *signinWork, *http.Cookie) {
	t.Helper()
	f := newChange(t, session.CredentialBearer)
	device, deviceCookie, _ := verificationDevice(t, f)
	flow, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	store, err := memory.New(memory.Options{MaxKeys: 128, Shards: 2})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: &signinShared{f.rate, store}, Namespace: "signin-test", IdentifierKey: [32]byte{1}, Now: f.clock.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	work := &signinWork{base: f, canonical: "person@example.test"}
	c := passwordhttp.SigninConfig{Network: f.config.Network, Service: work, Rate: rate, Origin: "https://tenant.example", FlowCookie: flow, SessionCookie: f.config.Cookie, Device: device, ActorID: "public-entry", PolicyRevision: 1, Audience: "identity-service", Now: f.clock.Now, MaximumDuration: 2 * time.Second, Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}}
	q := identity.RecoveryQuery{CommandID: "AQEBAQEBAQEBAQEBAQEBAQ", TenantID: "tenant-a", AnonymousFlowID: "AQEBAQEBAQEBAQEBAQEBAQ", ActorID: c.ActorID, ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.password.signin"}
	recovery, err := password.NewSigninRecovery(q, identity.PreAuthTransactionID(q.AnonymousFlowID))
	if err != nil {
		t.Fatal(err)
	}
	work.result = password.SigninResult{State: auth.SignInStateRejected, Recovery: recovery, Issuance: session.IssueResult{CommandID: q.CommandID, CommitOutcome: identity.CommitOutcomeNotCommitted}}
	return f, c, work, deviceCookie
}
func signinRequest(f *changeFixture, device *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/password/signin", strings.NewReader(`{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","identifier":"person@EXAMPLE.test","password":"synthetic-password","callbackURL":""}`))
	r.Host = "tenant.example"
	r.RemoteAddr = "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: f.wire})
	r.AddCookie(device)
	return r
}
func serveSignin(t *testing.T, c passwordhttp.SigninConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := passwordhttp.NewSigninHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestSigninPreservesOriginalCustodyAndDestroysPassword(t *testing.T) {
	f, c, work, device := newSignin(t)
	w := serveSignin(t, c, signinRequest(f, device))
	if w.Code != 403 || work.reads != 1 || work.calls != 1 || f.rate.calls != 2 || work.last.TenantID != "tenant-a" || work.last.Identifier != "person@EXAMPLE.test" || work.last.Network != "198.51.100.7" || work.last.Device == "" || work.last.Caller.CorrelationID == "" || work.last.Password.Len() != 0 {
		t.Fatalf("original transport or cleanup failed: status=%d reads=%d calls=%d rate=%d secretDestroyed=%t", w.Code, work.reads, work.calls, f.rate.calls, work.last.Password.Len() == 0)
	}
	if len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("rejection delivered credentials")
	}
	var out passwordhttp.SigninResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommitOutcome != "not_committed" || out.Recovery == nil || out.SignedIn {
		t.Fatal("original outcome lost")
	}
}

func signinIssuance(t *testing.T, f *changeFixture, c passwordhttp.SigninConfig, work *signinWork) {
	t.Helper()
	spec, err := f.reader.observation.Session.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	spec.Authentication.Proof.ID = auth.ProofID(work.result.Issuance.CommandID)
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	spec.Lookup, err = token.Digest(key, string(spec.TenantID))
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := session.NewCSRFToken()
	if err != nil {
		t.Fatal(err)
	}
	csrfKey, _ := session.NewCSRFKey(1, make([]byte, 32))
	state, err := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSessionWithCSRF(spec, state)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := c.SessionCookie.Attributes(spec.Remember, f.clock.Now(), spec.IssuedAt.Add(spec.Remember.AbsoluteTTL()))
	if err != nil {
		t.Fatal(err)
	}
	work.result.State = auth.SignInStateAuthenticated
	work.result.SessionID = spec.SessionID
	work.result.Issuance.CommitOutcome = identity.CommitOutcomeCommitted
	work.result.Issuance.Session = record
	work.result.Issuance.Token = token
	work.result.Issuance.Cookie = attributes
	work.result.CSRFToken = csrf
}
func TestSigninFreshCommitDeliversOriginalSessionAndSynchronizerOnce(t *testing.T) {
	f, c, work, device := newSignin(t)
	signinIssuance(t, f, c, work)
	original := work.result
	w := serveSignin(t, c, signinRequest(f, device))
	cookies := w.Result().Cookies()
	if w.Code != 200 || len(cookies) != 1 || cookies[0].Name != "__Host-identity_session" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].MaxAge != 0 || !cookies[0].Expires.IsZero() {
		t.Fatalf("fresh delivery failed status=%d cookies=%d", w.Code, len(cookies))
	}
	if _, err := session.ParseToken(cookies[0].Value); err != nil {
		t.Fatal("malformed session delivery")
	}
	if _, err := session.ParseCSRFToken(w.Header().Get("X-CSRF-Token")); err != nil {
		t.Fatal("missing synchronizer")
	}
	if _, err := original.Issuance.Token.Reveal(); err == nil {
		t.Fatal("original bearer not consumed")
	}
	if _, err := original.CSRFToken.Reveal(); err == nil {
		t.Fatal("original synchronizer not consumed")
	}
	var out passwordhttp.SigninResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.SignedIn || out.SessionID != "session-a" || out.CommitOutcome != "committed" || out.Recovery == nil {
		t.Fatal("fresh original metadata absent")
	}
	if strings.Contains(w.Body.String(), cookies[0].Value) || strings.Contains(w.Body.String(), w.Header().Get("X-CSRF-Token")) || strings.Contains(w.Body.String(), "person@") || strings.Contains(w.Body.String(), "synthetic-password") {
		t.Fatal("private material in JSON")
	}
}
func TestSigninAmbiguousOrForeignResultsNeverDeliver(t *testing.T) {
	for _, mode := range []string{"committed-error", "canceled", "unknown", "replay", "foreign-session", "foreign-proof", "foreign-cookie", "expired", "no-csrf"} {
		t.Run(mode, func(t *testing.T) {
			f, c, work, device := newSignin(t)
			signinIssuance(t, f, c, work)
			r := signinRequest(f, device)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			switch mode {
			case "committed-error":
				work.err = errors.New("private diagnostic")
			case "canceled":
				work.cancel = cancel
			case "unknown":
				work.result = password.SigninResult{State: auth.SignInStateRejected, Recovery: work.result.Recovery, Issuance: session.IssueResult{CommandID: work.result.Issuance.CommandID, CommitOutcome: identity.CommitOutcomeUnknown}}
			case "replay":
				work.result.Issuance.Replayed = true
				work.result.Issuance.Token = session.Token{}
				work.result.CSRFToken = session.CSRFToken{}
				work.result.Issuance.Cookie = http.Cookie{}
			case "foreign-session":
				work.result.SessionID = "other"
			case "foreign-proof":
				spec, _ := work.result.Issuance.Session.Bindings()
				spec.Authentication.Proof.ID = "AgICAgICAgICAgICAgICAg"
				record, err := session.NewSessionWithCSRF(spec, work.result.Issuance.Session.CSRFState())
				if err != nil {
					t.Fatal(err)
				}
				work.result.Issuance.Session = record
			case "foreign-cookie":
				work.result.Issuance.Cookie.Domain = "foreign.test"
			case "expired":
				f.clock.now = f.clock.now.Add(2 * time.Minute)
			case "no-csrf":
				work.result.CSRFToken = session.CSRFToken{}
			}
			w := serveSignin(t, c, r)
			if w.Code != 503 || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatalf("failed/foreign result delivered credentials status=%d", w.Code)
			}
			if strings.Contains(w.Body.String(), "private diagnostic") {
				t.Fatal("native diagnostic exposed")
			}
		})
	}
}

func TestSigninRejectsHostileInputBeforeNativeWork(t *testing.T) {
	for _, mode := range []string{"origin", "missing-origin", "plaintext", "host", "key", "authorization", "query", "trailer", "duplicate-cookie", "missing-device", "tampered-device", "unknown-field", "duplicate-json", "null-remember", "wrong-callback", "source-outage", "rate-outage"} {
		t.Run(mode, func(t *testing.T) {
			f, c, work, device := newSignin(t)
			r := signinRequest(f, device)
			want := 400
			rates, reads := 0, 0
			switch mode {
			case "origin":
				r.Header.Set("Origin", "https://foreign.test")
				want = 403
			case "missing-origin":
				r.Header.Del("Origin")
				want = 403
			case "plaintext":
				r.TLS = nil
				want = 403
			case "host":
				r.Host = "foreign.test"
				want = 421
			case "key":
				r.Header.Set("Idempotency-Key", "attempt")
			case "authorization":
				r.Header.Set("Authorization", "Bearer alternative")
			case "query":
				r.URL.RawQuery = "identifier=other"
			case "trailer":
				r.Trailer = http.Header{"Identifier": []string{"other"}}
			case "duplicate-cookie":
				r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: f.wire})
			case "missing-device":
				r.Header.Del("Cookie")
				r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: f.wire})
			case "tampered-device":
				r.Header.Del("Cookie")
				r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: f.wire})
				copy := *device
				copy.Value = "B" + copy.Value[1:]
				r.AddCookie(&copy)
			case "unknown-field", "duplicate-json", "null-remember", "wrong-callback":
				body := `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","identifier":"person@example.test","password":"synthetic-password","callbackURL":""`
				switch mode {
				case "unknown-field":
					body += `,"userID":"foreign"}`
				case "duplicate-json":
					body += `,"identifier":"other"}`
				case "null-remember":
					body += `,"remember":null}`
				case "wrong-callback":
					body = strings.Replace(body, `"callbackURL":""`, `"callbackURL":"https://foreign.test"`, 1) + `}`
				}
				r.Body = io.NopCloser(strings.NewReader(body))
				r.ContentLength = int64(len(body))
			case "source-outage":
				work.sourceErr = errors.New("private source")
				want, rates, reads = 503, 1, 1
			case "rate-outage":
				f.rate.fail = true
				want, rates = 503, 1
			}
			w := serveSignin(t, c, r)
			if w.Code != want || work.calls != 0 || work.reads != reads || f.rate.calls != rates || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatalf("hostile input reached work status=%d calls=%d reads=%d rate=%d", w.Code, work.calls, work.reads, f.rate.calls)
			}
		})
	}
}

func TestSigninFeatureOptInAndActualWire(t *testing.T) {
	f, c, work, device := newSignin(t)
	signinIssuance(t, f, c, work)
	feature, err := passwordhttp.NewSigninFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	if work.reads != 0 || work.calls != 0 || f.rate.calls != 0 {
		t.Fatal("constructor performed IO")
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Signin", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, signinRequest(f, device))
	if w.Code != 200 || len(doc.Operations()) != 1 || !strings.Contains(string(doc.JSON()), `"identity.password.signin"`) {
		t.Fatal("selected real route/wire absent")
	}
	parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, key := range []string{"paths", "/v1/password/signin", "post", "responses", "200", "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(key)
		if !ok {
			t.Fatal("missing actual response schema")
		}
	}
	instance, err := parse.JSON(context.Background(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
	if err != nil || !report.Valid() {
		t.Fatalf("actual signin response rejected: %v %+v", err, report.Diagnostics())
	}
	_, disabled, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Disabled", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil || len(disabled.Operations()) != 0 {
		t.Fatal("disabled selection advertised operation")
	}
}

func TestSigninMiddlewareCannotManufactureCredentials(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "unwind", true: "short-circuit"}[stop], func(t *testing.T) {
			f, c, work, device := newSignin(t)
			signinIssuance(t, f, c, work)
			m := []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "inject", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if stop {
						w.Header()["set-cookie"] = []string{"forged=credential"}
						w.Header()["x-csrf-token"] = []string{"forged"}
						w.Header().Set("Trailer", "Set-Cookie")
						w.WriteHeader(202)
						return
					}
					next.ServeHTTP(w, r)
					w.Header()["set-cookie"] = []string{"forged=credential"}
					w.Header()["x-csrf-token"] = []string{"forged"}
					w.Header().Set(http.TrailerPrefix+"Set-Cookie", "forged=credential")
				})
			}}}}
			h, err := passwordhttp.NewSigninHandlerWithMiddleware(c, m)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, signinRequest(f, device))
			if stop {
				if w.Code != 202 || work.calls != 0 || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("hook minted credential")
				}
			} else {
				if w.Code != 200 || len(w.Result().Cookies()) != 1 || strings.Contains(w.Header().Get("Set-Cookie"), "forged") || w.Header().Get("X-CSRF-Token") == "forged" {
					t.Fatal("hook replaced original delivery")
				}
			}
			for name := range w.Header() {
				if strings.HasPrefix(name, http.TrailerPrefix) || strings.EqualFold(name, "Trailer") {
					t.Fatal("hook left response trailer")
				}
			}
		})
	}
}

func TestSigninConstructionRejectsUnsafeOrMissingOwners(t *testing.T) {
	for _, mode := range []string{"service", "typed-nil", "rate", "clock", "policy", "duration", "origin", "flow", "device", "cookie-collision", "lifetime", "callback", "audience"} {
		t.Run(mode, func(t *testing.T) {
			f, c, work, _ := newSignin(t)
			switch mode {
			case "service":
				c.Service = nil
			case "typed-nil":
				c.Service = (*signinWork)(nil)
			case "rate":
				c.Rate = nil
			case "clock":
				c.Now = nil
			case "policy":
				c.PolicyRevision = 0
			case "duration":
				c.MaximumDuration = 31 * time.Second
			case "origin":
				c.Origin = "http://tenant.example"
			case "flow":
				c.FlowCookie = c.SessionCookie
			case "device":
				c.Device = session.BrowserDeviceConfig{}
			case "cookie-collision":
				c.SessionCookie = c.Device.Cookie
			case "lifetime":
				c.Lifetime = session.LifetimeConfig{}
			case "callback":
				c.CallbackURL = "http://foreign.test/path"
			case "audience":
				c.Audience = "control\nvalue"
			}
			if h, err := passwordhttp.NewSigninHandler(c); err == nil || h != nil {
				t.Fatal("unsafe/missing configuration accepted")
			}
			if work.calls != 0 || work.reads != 0 || f.rate.calls != 0 {
				t.Fatal("constructor performed IO")
			}
		})
	}
}
