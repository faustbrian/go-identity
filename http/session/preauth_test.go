package sessionhttp_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

type preAuthExecutor struct {
	mode  string
	calls atomic.Int32
	last  session.PreAuthIssueCommand
}

func (e *preAuthExecutor) ExecutePreAuthIssuance(ctx context.Context, c session.PreAuthIssueCommand) (session.PreAuthIssueExecution, error) {
	e.calls.Add(1)
	e.last = c
	if _, ok := ctx.Deadline(); !ok {
		return session.PreAuthIssueExecution{}, errors.New("unbounded")
	}
	s, _ := c.Record.Bindings()
	b := identity.CommandBinding{CommandID: c.CommandID, TenantID: s.Binding.Intent.TenantID, AnonymousFlowID: string(s.Binding.ID), ActorID: "preauth-service", ActorKind: authorization.SubjectServiceAccount, OperationID: "identity.session.preauth-issue", RecordID: string(s.Binding.ID), PolicyID: s.Binding.Intent.PolicyID, PolicyVersion: s.Binding.Intent.PolicyVersion, SchemaID: "session-preauth-issue-v1", SchemaVersion: 1, CorrelationID: c.CorrelationID}
	out := session.PreAuthIssueExecution{Receipt: identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit", Feature: &identity.FeatureReceipt{Operation: session.PreAuthIssueOperation(), AfterVersion: 1}}}
	switch e.mode {
	case "unknown":
		return session.PreAuthIssueExecution{}, identity.UnknownCommitError{CommandID: c.CommandID}
	case "error":
		return out, errors.New("private dependency diagnostic")
	case "replay":
		out.Replayed = true
	}
	return out, nil
}
func (*preAuthExecutor) RecoverPreAuthIssue(context.Context, identity.RecoveryQuery) (identity.CommandResult, error) {
	return identity.CommandResult{}, errors.New("not selected")
}

type preAuthOwner struct {
	issuer   *session.PreAuthIssuer
	prepares atomic.Int32
	input    session.PreAuthPrepareInput
	mutate   func(session.PreAuthIssueResult) session.PreAuthIssueResult
}

func (s *preAuthOwner) Prepare(ctx context.Context, i session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error) {
	s.prepares.Add(1)
	s.input = i
	if ctx.Err() != nil {
		return session.PreparedPreAuthIssuance{}, ctx.Err()
	}
	return s.issuer.Prepare(i)
}
func (s *preAuthOwner) Issue(ctx context.Context, p session.PreparedPreAuthIssuance) (session.PreAuthIssueResult, error) {
	out, err := s.issuer.Issue(ctx, p)
	if s.mutate != nil {
		out = s.mutate(out)
	}
	return out, err
}

func preAuthHTTPFixture(t *testing.T) (sessionhttp.PreAuthConfig, *preAuthOwner, *preAuthExecutor) {
	t.Helper()
	f := newFixture(t, session.CredentialCookie)
	now := f.config.Now
	store, err := memory.New(memory.Options{MaxKeys: 1024, Shards: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: &shared{store}, Namespace: "preauth-http", Now: now, IdentifierKey: [32]byte{1}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewDigestKey(1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	executor := &preAuthExecutor{}
	issuer, err := session.NewPreAuthIssuer(executor, session.PreAuthIssuerConfig{ActorID: "preauth-service", Action: "otp-signin", Origin: "https://tenant.example", PolicyID: "otp-policy", PolicyVersion: 1, Clock: clock(now), MaximumDuration: time.Second, FlowTTL: 5 * time.Minute, LookupKey: key, TokenSize: 32, Cookie: cookie})
	if err != nil {
		t.Fatal(err)
	}
	owner := &preAuthOwner{issuer: issuer}
	return sessionhttp.PreAuthConfig{Network: f.config.Network, Service: owner, Rate: rate, Cookie: cookie, Now: now, MaximumDuration: 2 * time.Second, Action: "otp-signin", Origin: identityhttp.Origin("https://tenant.example"), PolicyID: "otp-policy", PolicyVersion: 1, Lifetime: session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute}}, owner, executor
}

func preAuthHTTPRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/session/preauth-issue", strings.NewReader(body))
	r.Host = "tenant.example"
	r.RemoteAddr = "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Origin", "https://tenant.example")
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestPreAuthHTTPOriginalCommitAndRemember(t *testing.T) {
	for _, tc := range []struct {
		body   string
		choice session.RememberChoice
	}{{"{}", session.BrowserSession}, {`{"remember":false}`, session.BrowserSession}, {`{"remember":true}`, session.PersistentSession}} {
		c, owner, executor := preAuthHTTPFixture(t)
		h, err := sessionhttp.NewPreAuthHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest(tc.body))
		var out sessionhttp.PreAuthResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Issued || out.FlowID == "" || out.CommandID == "" || out.CommitOutcome != "committed" || out.ExpiresAt.Sub(out.IssuedAt) != 5*time.Minute {
			t.Fatal("original issuance missing", w.Code)
		}
		if owner.prepares.Load() != 1 || executor.calls.Load() != 1 || owner.input.Remember.Choice() != tc.choice {
			t.Fatal("owner or remember policy not retained")
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != "__Host-identity_flow" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].Domain != "" || cookies[0].MaxAge != 300 || cookies[0].SameSite != http.SameSiteLaxMode {
			t.Fatal("unsafe or missing original flow cookie")
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || strings.Contains(w.Body.String(), cookies[0].Value) {
			t.Fatal("flow credential escaped cookie custody")
		}
		second := httptest.NewRecorder()
		h.ServeHTTP(second, preAuthHTTPRequest(tc.body))
		var fresh sessionhttp.PreAuthResponse
		if second.Code != 200 || json.Unmarshal(second.Body.Bytes(), &fresh) != nil || fresh.CommandID == out.CommandID || fresh.FlowID == out.FlowID {
			t.Fatal("deliberate fresh start became retry")
		}
	}
}

func TestPreAuthHTTPAdmissionPrecedesPreparation(t *testing.T) {
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Host = "unmapped.example" },
		func(r *http.Request) { r.TLS = nil },
		func(r *http.Request) { r.Header.Del("Origin") },
		func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") },
		func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer forbidden") },
		func(r *http.Request) { r.URL.RawQuery = "remember=true" },
	} {
		c, owner, executor := preAuthHTTPFixture(t)
		h, err := sessionhttp.NewPreAuthHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		r := preAuthHTTPRequest("{}")
		change(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code == 200 || owner.prepares.Load() != 0 || executor.calls.Load() != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("invalid initiation reached entropy or durable owner")
		}
	}
	c, owner, executor := preAuthHTTPFixture(t)
	h, err := sessionhttp.NewPreAuthHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 21; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest("{}"))
		if i < 20 && w.Code != 200 || i == 20 && (w.Code != 429 || w.Header().Get("Retry-After") != "30" || len(w.Header().Values("Set-Cookie")) != 0) {
			t.Fatal("original flow admission ceiling", i, w.Code)
		}
	}
	if owner.prepares.Load() != 20 || executor.calls.Load() != 20 {
		t.Fatal("exhausted admission reached owner")
	}
}

func TestPreAuthHTTPNeverDeliversReplayUnknownOrError(t *testing.T) {
	for _, mode := range []string{"unknown", "error", "replay"} {
		c, owner, executor := preAuthHTTPFixture(t)
		executor.mode = mode
		h, err := sessionhttp.NewPreAuthHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest("{}"))
		var out sessionhttp.PreAuthResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Issued || out.CommandID == "" || len(w.Header().Values("Set-Cookie")) != 0 || owner.prepares.Load() != 1 || executor.calls.Load() != 1 {
			t.Fatal("nonoriginal delivery or automatic retry", mode, w.Code)
		}
		if mode == "unknown" && out.CommitOutcome != "unknown" || mode != "unknown" && out.CommitOutcome != "committed" {
			t.Fatal("native outcome lost", mode)
		}
	}
}

func TestPreAuthHTTPClosedInputAndComposition(t *testing.T) {
	for _, body := range []string{`{"remember":null}`, `{"remember":1}`, `{"remember":"true"}`, `{"remember":true,"remember":false}`, `{"Remember":true}`, `{"tenantID":"tenant-b"}`, `{"callbackURL":"https://foreign.example"}`, `{} {}`, `{"remember":false,"idempotencyKey":"alternative"}`} {
		c, owner, executor := preAuthHTTPFixture(t)
		h, err := sessionhttp.NewPreAuthHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest(body))
		if w.Code != 400 || owner.prepares.Load() != 0 || executor.calls.Load() != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("untrusted input reached owner")
		}
	}
	for _, change := range []func(*sessionhttp.PreAuthConfig){
		func(c *sessionhttp.PreAuthConfig) { c.Service = nil },
		func(c *sessionhttp.PreAuthConfig) { var p *preAuthOwner; c.Service = p },
		func(c *sessionhttp.PreAuthConfig) { c.Rate = nil },
		func(c *sessionhttp.PreAuthConfig) { c.Now = nil },
		func(c *sessionhttp.PreAuthConfig) { c.Origin = "http://tenant.example" },
		func(c *sessionhttp.PreAuthConfig) { c.Action = "" },
		func(c *sessionhttp.PreAuthConfig) { c.PolicyVersion = 0 },
		func(c *sessionhttp.PreAuthConfig) { c.CallbackURL = "https://foreign.example/#fragment" },
		func(c *sessionhttp.PreAuthConfig) { c.Cookie = session.CookiePolicy{} },
		func(c *sessionhttp.PreAuthConfig) { c.Lifetime.Default = session.RememberDefault },
		func(c *sessionhttp.PreAuthConfig) { c.MaximumDuration = 0 },
	} {
		c, owner, executor := preAuthHTTPFixture(t)
		change(&c)
		if h, err := sessionhttp.NewPreAuthHandler(c); err == nil || h != nil || owner.prepares.Load() != 0 || executor.calls.Load() != 0 {
			t.Fatal("invalid composition admitted or performed IO")
		}
	}
}

func TestPreAuthHTTPRejectsMismatchedCustodyAndCancellation(t *testing.T) {
	for _, change := range []func(*sessionhttp.PreAuthConfig, *preAuthOwner){
		func(c *sessionhttp.PreAuthConfig, _ *preAuthOwner) { c.Action = "other-signin" },
		func(_ *sessionhttp.PreAuthConfig, s *preAuthOwner) {
			s.mutate = func(o session.PreAuthIssueResult) session.PreAuthIssueResult {
				o.CommandID = "foreign-command"
				return o
			}
		},
		func(_ *sessionhttp.PreAuthConfig, s *preAuthOwner) {
			s.mutate = func(o session.PreAuthIssueResult) session.PreAuthIssueResult {
				o.Flow = session.PreAuthTransaction{}
				return o
			}
		},
		func(_ *sessionhttp.PreAuthConfig, s *preAuthOwner) {
			s.mutate = func(o session.PreAuthIssueResult) session.PreAuthIssueResult { o.Cookie.Domain = "."; return o }
		},
		func(_ *sessionhttp.PreAuthConfig, s *preAuthOwner) {
			s.mutate = func(o session.PreAuthIssueResult) session.PreAuthIssueResult { o.Cookie.Secure = false; return o }
		},
		func(_ *sessionhttp.PreAuthConfig, s *preAuthOwner) {
			s.mutate = func(o session.PreAuthIssueResult) session.PreAuthIssueResult { o.Cookie.MaxAge = 301; return o }
		},
	} {
		c, owner, _ := preAuthHTTPFixture(t)
		change(&c, owner)
		h, err := sessionhttp.NewPreAuthHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest("{}"))
		if w.Code != 503 || len(w.Result().Cookies()) != 0 {
			t.Fatal("mismatched native result delivered", w.Code)
		}
	}
	c, owner, executor := preAuthHTTPFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner.mutate = func(o session.PreAuthIssueResult) session.PreAuthIssueResult { cancel(); return o }
	h, err := sessionhttp.NewPreAuthHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest("{}").WithContext(ctx))
	var out sessionhttp.PreAuthResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Issued || out.CommitOutcome != "committed" || len(w.Result().Cookies()) != 0 || executor.calls.Load() != 1 {
		t.Fatal("postcommit cancellation lost outcome or delivered cookie")
	}
}

func TestPreAuthHTTPMiddlewareRetainsOriginalAdmissionAndResponse(t *testing.T) {
	c, owner, executor := preAuthHTTPFixture(t)
	var observed atomic.Int32
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Host = "foreign.example"
			r.Header.Set("Origin", "https://foreign.example")
			w.Header().Set("Set-Cookie", "attacker=forbidden")
			next.ServeHTTP(w, r)
			next.ServeHTTP(w, r)
		})
	}
	after := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state, ok := identityhttp.PipelineValue[sessionhttp.PreAuthState](r)
			out, attempted := state.Attempt()
			if !ok || !attempted || !out.Issued || out.CommitOutcome != "committed" {
				t.Error("after hook lacks original attempted outcome")
			}
			observed.Add(1)
			w.Header().Set("Set-Cookie", "attacker=forbidden")
			next.ServeHTTP(w, r)
		})
	}
	middleware := []identityhttp.MiddlewareDescriptor{
		{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "original", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: wrap}},
		{Owner: "identity/session", Middleware: identityhttp.Middleware{Name: "observed", Phase: identityhttp.MiddlewareAfterHandler, Order: 1, Handler: after}},
	}
	h, err := sessionhttp.NewPreAuthHandlerWithMiddleware(c, middleware)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest("{}"))
	cookies := w.Result().Cookies()
	if w.Code != 200 || len(cookies) != 1 || cookies[0].Name != "__Host-identity_flow" || owner.prepares.Load() != 1 || executor.calls.Load() != 1 || observed.Load() != 1 {
		t.Fatal("hook replaced original admission/response or repeated issuance")
	}
}

func TestPreAuthHTTPPanicAndEarlyCancellationStayCredentialFree(t *testing.T) {
	c, owner, executor := preAuthHTTPFixture(t)
	owner.mutate = func(session.PreAuthIssueResult) session.PreAuthIssueResult { panic("private dependency diagnostic") }
	h, err := sessionhttp.NewPreAuthHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest("{}"))
	var out sessionhttp.PreAuthResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Issued || out.CommitOutcome != "unknown" || out.CommandID == "" || len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), "private") {
		t.Fatal("panic lost original ambiguity or exposed custody")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest("{}").WithContext(ctx))
	if w.Code != 503 || owner.prepares.Load() != 1 || executor.calls.Load() != 1 || len(w.Result().Cookies()) != 0 {
		t.Fatal("pre-canceled input reached preparation")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, nil)
	if w.Code != 400 || len(w.Result().Cookies()) != 0 {
		t.Fatal("nil request did not fail closed")
	}
}

type cancelPreAuthBody struct{ cancel context.CancelFunc }

func (b cancelPreAuthBody) Read([]byte) (int, error) {
	b.cancel()
	return 0, context.Canceled
}
func (cancelPreAuthBody) Close() error { return nil }

func TestPreAuthHTTPCancellationDuringBodyReadIsUnavailable(t *testing.T) {
	c, owner, executor := preAuthHTTPFixture(t)
	h, err := sessionhttp.NewPreAuthHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := preAuthHTTPRequest("{}").WithContext(ctx)
	r.Body = cancelPreAuthBody{cancel: cancel}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"error":"unavailable"`) || owner.prepares.Load() != 0 || executor.calls.Load() != 0 || len(w.Result().Cookies()) != 0 {
		t.Fatalf("body cancellation classified as %d or reached issuance", w.Code)
	}
	// Cancellation during input admission must leave the complete IP budget intact.
	for i := 0; i < 20; i++ {
		w = httptest.NewRecorder()
		h.ServeHTTP(w, preAuthHTTPRequest("{}"))
		if w.Code != 200 {
			t.Fatalf("canceled decoding consumed rate budget: request %d returned %d", i+1, w.Code)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, preAuthHTTPRequest("{}"))
	if w.Code != 429 || owner.prepares.Load() != 20 || executor.calls.Load() != 20 {
		t.Fatal("original-flow rate ceiling changed")
	}
}
