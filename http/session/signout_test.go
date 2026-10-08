package sessionhttp_test

import (
	"context"
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
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
)

type logoutExecutor func(context.Context, session.RevokeOneRequest) (identity.CommandResult, error)

func (f logoutExecutor) ExecuteRevokeOne(c context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
	return f(c, r)
}
func (f logoutExecutor) ExecuteRevokeOneWithCSRF(c context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
	return f(c, r)
}

type logoutFixture struct {
	*fixture
	config         sessionhttp.SignOutConfig
	csrf           string
	executions     int
	outcome        identity.CommitOutcome
	executionError error
	recovery       identity.RecoveryQuery
	after          func()
}

func newLogout(t *testing.T, mode session.CredentialKind) *logoutFixture {
	t.Helper()
	f := &logoutFixture{fixture: newFixture(t, mode), outcome: identity.CommitOutcomeCommitted}
	key, _ := session.NewCSRFKey(1, make([]byte, 32))
	token, _ := session.NewCSRFToken()
	f.csrf, _ = token.Reveal()
	spec, _ := f.observation.Session.Bindings()
	state, err := token.Digest(key, session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version})
	if err != nil {
		t.Fatal(err)
	}
	f.observation.Session, err = session.NewSessionWithCSRF(spec, state)
	if err != nil {
		t.Fatal(err)
	}
	executor := logoutExecutor(func(ctx context.Context, r session.RevokeOneRequest) (identity.CommandResult, error) {
		f.executions++
		if ctx.Err() != nil {
			t.Fatal("executor entered with canceled context")
		}
		command, ok := r.Command()
		if !ok {
			t.Fatal("missing owned command")
		}
		one, ok := command.RevokeOne()
		if !ok {
			t.Fatal("wrong command")
		}
		b, _ := one.Session.Bindings()
		if b.SessionID != "session-a" || b.UserID != "user-a" || b.TenantID != "tenant-a" {
			t.Fatal("not exact self target")
		}
		if mode == session.CredentialCookie {
			proof, ok := r.CSRFToken()
			if !ok || state.Check(session.CSRFBinding{TenantID: b.TenantID, SessionID: b.SessionID, SessionVersion: b.Version}, proof, key) != nil {
				t.Fatal("transaction did not receive bound CSRF custody")
			}
		} else if _, ok := r.CSRFToken(); ok {
			t.Fatal("bearer acquired cookie CSRF")
		}
		binding := one.Binding
		f.recovery = identity.RecoveryQuery{CommandID: binding.CommandID, TenantID: binding.TenantID, UserID: binding.UserID, ActorID: binding.ActorID, ActorKind: binding.ActorKind, OperationID: binding.OperationID, RecordID: binding.RecordID, LinkMode: binding.LinkMode}
		result := identity.CommandResult{Binding: binding, Outcome: f.outcome, Feature: &identity.FeatureReceipt{Operation: session.RevokeOneOperation()}}
		if f.outcome == identity.CommitOutcomeCommitted {
			result.AuditEventID = "audit-signout"
			result.Feature.BeforeVersion = b.Version
			result.Feature.AfterVersion = b.Version + 1
			f.observation.Active = false
		}
		if f.outcome == identity.CommitOutcomeInProgress {
			result.RetryAfter = time.Second
		}
		if result.Validate() != nil {
			t.Fatal("bad fixture receipt")
		}
		if f.after != nil {
			f.after()
		}
		return result, f.executionError
	})
	base, err := session.NewSignOutService(f.fixture.config.Sessions, executor, session.SignOutConfig{Cookie: f.fixture.config.Cookie, PolicyID: "session-self", PolicyVersion: 1, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookieSignOutService(base, []session.CSRFKey{key})
	if err != nil {
		t.Fatal(err)
	}
	f.config = sessionhttp.SignOutConfig{GetConfig: f.fixture.config, TrustedOrigins: []identityhttp.Origin{"https://tenant.example"}}
	if mode == session.CredentialCookie {
		f.config.CookieSignOut = cookie
	} else {
		f.config.BearerSignOut = base
		f.config.TrustedOrigins = nil
	}
	return f
}

func logoutRequest(f *logoutFixture, credential bool) *http.Request {
	r := request(f.fixture, credential)
	r.Method = http.MethodPost
	r.URL.Path = "/v1/session/signout"
	r.RequestURI = r.URL.Path
	r.Body = http.NoBody
	r.ContentLength = 0
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if f.config.Transport == session.CredentialCookie {
		r.Header.Set("Origin", "https://tenant.example")
		if credential {
			r.Header.Set("X-CSRF-Token", f.csrf)
		}
	}
	return r
}

func logoutServe(t *testing.T, f *logoutFixture, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := sessionhttp.NewSignOutHandler(f.config)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("logout cacheable")
	}
	for _, secret := range []string{f.wire, f.csrf, "private backend diagnostic"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("secret disclosed")
		}
	}
	return w
}

func TestSignOutHTTPCommitsExactSelfAndClearsOnlySelectedTransport(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newLogout(t, mode)
		w := logoutServe(t, f, logoutRequest(f, true))
		var out sessionhttp.SignOutResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.SignedOut || out.CommitOutcome != "committed" || f.executions != 1 || f.observation.Active {
			t.Fatalf("self signout not committed: status=%d", w.Code)
		}
		if out.Recovery == nil || out.Recovery.CommandID != f.recovery.CommandID || out.Recovery.ActorID != f.recovery.ActorID || out.Recovery.ActorKind != f.recovery.ActorKind || out.Recovery.TenantID != f.recovery.TenantID || out.Recovery.UserID != f.recovery.UserID || out.Recovery.OperationID != f.recovery.OperationID || out.CommandID != f.recovery.CommandID {
			t.Fatal("original recovery scope lost")
		}
		if mode == session.CredentialCookie {
			cookies := w.Result().Cookies()
			if len(cookies) != 1 {
				t.Fatal("missing exact cookie removal")
			}
			c := cookies[0]
			if c.Name != "__Host-identity_session" || c.Value != "" || c.Path != "/" || c.Domain != "" || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.MaxAge != -1 || !c.Expires.Equal(time.Unix(1, 0)) || out.ClearBearer {
				t.Fatal("unsafe cookie removal")
			}
		} else if !out.ClearBearer || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("bearer logout changed cookie or failed to clear caller bearer")
		}
	}
}

func TestSignOutHTTPAbsentInactiveAndActiveMissingCSRF(t *testing.T) {
	for _, absent := range []bool{true, false} {
		f := newLogout(t, session.CredentialCookie)
		f.observation.Active = false
		r := logoutRequest(f, !absent)
		r.Header.Del("X-CSRF-Token")
		w := logoutServe(t, f, r)
		if w.Code != 200 || f.executions != 0 || len(w.Result().Cookies()) != 1 {
			t.Fatal("absent/inactive logout requires impossible active token")
		}
	}
	f := newLogout(t, session.CredentialCookie)
	r := logoutRequest(f, true)
	r.Header.Del("X-CSRF-Token")
	w := logoutServe(t, f, r)
	if w.Code != 403 || f.executions != 0 || !f.observation.Active || len(w.Result().Cookies()) != 0 {
		t.Fatal("active cookie logout bypassed CSRF")
	}
}

func TestSignOutHTTPPreservesAmbiguousAndRejectedOutcomes(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeUnknown, identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeInProgress, identity.CommitOutcomeCommitted} {
		f := newLogout(t, session.CredentialCookie)
		f.outcome = outcome
		if outcome == identity.CommitOutcomeCommitted {
			f.executionError = errors.New("private backend diagnostic")
		}
		w := logoutServe(t, f, logoutRequest(f, true))
		var out sessionhttp.SignOutResponse
		if w.Code == 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.SignedOut || out.ClearBearer || len(w.Result().Cookies()) != 0 || f.executions != 1 || out.Recovery == nil || out.CommandID != f.recovery.CommandID || out.Recovery.CommandID != f.recovery.CommandID || out.Recovery.RecordID != f.recovery.RecordID {
			t.Fatalf("unsafe failed outcome=%d status=%d", outcome, w.Code)
		}
		if outcome == identity.CommitOutcomeUnknown && out.CommitOutcome != "unknown" {
			t.Fatal("unknown converted into rollback")
		}
		if outcome == identity.CommitOutcomeCommitted && out.CommitOutcome != "committed" {
			t.Fatal("observed commit lost on delivery error")
		}
	}
}

func TestSignOutHTTPRejectsOriginCredentialAndBodyAlternatives(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		mutate func(*http.Request)
	}{
		{"missing-origin", 403, func(r *http.Request) { r.Header.Del("Origin") }},
		{"null-origin", 403, func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"wrong-origin", 403, func(r *http.Request) { r.Header.Set("Origin", "https://other.example") }},
		{"duplicate-origin", 400, func(r *http.Request) { r.Header.Add("origin", "https://tenant.example") }},
		{"referer-no-fallback", 403, func(r *http.Request) { r.Header.Del("Origin"); r.Header.Set("Referer", "https://tenant.example/") }},
		{"duplicate-csrf", 400, func(r *http.Request) { r.Header.Add("x-csrf-token", r.Header.Get("X-CSRF-Token")) }},
		{"empty-csrf", 400, func(r *http.Request) { r.Header.Set("X-CSRF-Token", "") }},
		{"both-channels", 400, func(r *http.Request) {
			body := "csrf_token=" + r.Header.Get("X-CSRF-Token")
			r.Body = io.NopCloser(strings.NewReader(body))
			r.ContentLength = int64(len(body))
		}},
		{"duplicate-cookie", 400, func(r *http.Request) { r.Header.Add("Cookie", r.Header.Get("Cookie")) }},
		{"mixed-credential", 400, func(r *http.Request) { r.Header.Set("Authorization", "Bearer unused") }},
		{"proxy-credential", 400, func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Bearer unused") }},
		{"retry-key", 400, func(r *http.Request) { r.Header.Set("Idempotency-Key", "key") }},
		{"query", 400, func(r *http.Request) { r.URL.RawQuery = "tenant_id=other" }},
		{"unknown-host", 421, func(r *http.Request) { r.Host = "unknown.example" }},
		{"plaintext", 400, func(r *http.Request) { r.TLS = nil }},
		{"wrong-method", 405, func(r *http.Request) { r.Method = http.MethodGet }},
		{"unsupported-media", 400, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
		{"compressed", 400, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
		{"target-form", 400, func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("userID=other")); r.ContentLength = 12 }},
		{"target-json", 400, func(r *http.Request) {
			r.Header.Set("Content-Type", "application/json")
			r.Body = io.NopCloser(strings.NewReader(`{"userID":"other"}`))
			r.ContentLength = 18
		}},
		{"trailing-json", 400, func(r *http.Request) {
			r.Header.Set("Content-Type", "application/json")
			r.Body = io.NopCloser(strings.NewReader(`{} {}`))
			r.ContentLength = 5
		}},
		{"oversize", 400, func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("a", 1025)))
			r.ContentLength = 1025
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newLogout(t, session.CredentialCookie)
			r := logoutRequest(f, true)
			tc.mutate(r)
			w := logoutServe(t, f, r)
			if w.Code != tc.status || f.calls.Load() != 0 || f.executions != 0 || !f.observation.Active || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("input reached owner or changed transport: status=%d reads=%d", w.Code, f.calls.Load())
			}
		})
	}
}

func TestSignOutHTTPValidChannelsAndWrongSessionToken(t *testing.T) {
	for _, media := range []string{"form", "json"} {
		f := newLogout(t, session.CredentialCookie)
		r := logoutRequest(f, true)
		body := "{}"
		r.Header.Set("Content-Type", "application/json")
		if media == "form" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Del("X-CSRF-Token")
			body = "csrf_token=" + f.csrf
		}
		r.Body = io.NopCloser(strings.NewReader(body))
		r.ContentLength = int64(len(body))
		if w := logoutServe(t, f, r); w.Code != 200 || f.executions != 1 || f.observation.Active {
			t.Fatal("valid canonical channel denied")
		}
		// Already inactive succeeds without a token or another protected command.
		r = logoutRequest(f, true)
		r.Header.Del("X-CSRF-Token")
		if w := logoutServe(t, f, r); w.Code != 200 || f.executions != 1 {
			t.Fatal("repeat signout mutated again")
		}
	}
	f := newLogout(t, session.CredentialCookie)
	r := logoutRequest(f, true)
	other, _ := session.NewCSRFToken()
	wire, _ := other.Reveal()
	r.Header.Set("X-CSRF-Token", wire)
	if w := logoutServe(t, f, r); w.Code != 403 || f.executions != 0 || !f.observation.Active || len(w.Result().Cookies()) != 0 {
		t.Fatal("well-shaped wrong CSRF granted authority")
	}
	// Explicit bearer ignores even a valid ambient session cookie and Origin.
	f = newLogout(t, session.CredentialBearer)
	r = logoutRequest(f, false)
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: f.wire})
	r.Header.Set("Origin", "null")
	if w := logoutServe(t, f, r); w.Code != 200 || f.executions != 0 || f.calls.Load() != 0 || len(w.Result().Cookies()) != 0 || !f.observation.Active {
		t.Fatal("absent bearer fell back to cookie")
	}
	r = logoutRequest(f, true)
	r.Header.Set("X-CSRF-Token", f.csrf)
	if w := logoutServe(t, f, r); w.Code != 400 || f.executions != 0 {
		t.Fatal("bearer accepted unused CSRF channel")
	}
}

func TestSignOutHTTPRateOutageAndCancellationNeverClear(t *testing.T) {
	f := newLogout(t, session.CredentialCookie)
	for range 100 {
		if w := logoutServe(t, f, logoutRequest(f, false)); w.Code != 200 {
			t.Fatal("within-budget absent logout denied")
		}
	}
	w := logoutServe(t, f, logoutRequest(f, true))
	if w.Code != 429 || w.Header().Get("Retry-After") == "" || f.executions != 0 || !f.observation.Active || len(w.Result().Cookies()) != 0 {
		t.Fatal("rate denial changed session or transport")
	}
	f = newLogout(t, session.CredentialCookie)
	f.fail.Store(true)
	if w := logoutServe(t, f, logoutRequest(f, true)); w.Code != 503 || len(w.Result().Cookies()) != 0 || f.executions != 0 {
		t.Fatal("owner outage reported logout")
	}
	f = newLogout(t, session.CredentialCookie)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w := logoutServe(t, f, logoutRequest(f, true).WithContext(ctx)); w.Code != 503 || f.calls.Load() != 0 || len(w.Result().Cookies()) != 0 {
		t.Fatal("canceled request entered owner")
	}
	f = newLogout(t, session.CredentialCookie)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	f.after = cancel
	w = logoutServe(t, f, logoutRequest(f, true).WithContext(ctx))
	var out sessionhttp.SignOutResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommitOutcome != "committed" || out.SignedOut || out.Recovery == nil || len(w.Result().Cookies()) != 0 || f.observation.Active {
		t.Fatal("post-commit cancellation lost outcome or cleared cookie")
	}
}

func TestSignOutHTTPRejectsInvalidCompositionAndCookieMismatch(t *testing.T) {
	f := newLogout(t, session.CredentialCookie)
	for _, mutate := range []func(*sessionhttp.SignOutConfig){
		func(c *sessionhttp.SignOutConfig) { c.CookieSignOut = nil },
		func(c *sessionhttp.SignOutConfig) { c.TrustedOrigins = nil },
		func(c *sessionhttp.SignOutConfig) { c.TrustedOrigins = []identityhttp.Origin{"*"} },
		func(c *sessionhttp.SignOutConfig) { c.Rate = nil },
		func(c *sessionhttp.SignOutConfig) { c.Sessions = nil },
		func(c *sessionhttp.SignOutConfig) { c.Transport = 0 },
	} {
		c := f.config
		mutate(&c)
		if h, err := sessionhttp.NewSignOutHandler(c); h != nil || err == nil {
			t.Fatal("invalid logout composition accepted")
		}
	}
	f.config.Cookie, _ = session.NewCookiePolicy(session.CookieConfig{Name: "__Host-other", SameSite: http.SameSiteStrictMode})
	r := logoutRequest(f, true)
	r.Header.Set("Cookie", "__Host-other="+f.wire)
	w := logoutServe(t, f, r)
	if w.Code != 503 || len(w.Result().Cookies()) != 0 || f.observation.Active || f.executions != 1 {
		t.Fatal("miscomposed cookie cleared wrong transport or lost committed outcome")
	}
}
