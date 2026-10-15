package passwordhttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// Risk plan: acquire only the original strict bearer; reject every client retry
// key/target override; count IP+current subject before one native invocation;
// preserve unchanged session validity across hooks/rate/native work; release
// owned password on all paths; proof projection only on fresh known commit.
// Native persistence, signing, counted risk and credential validation remain
// real platform adapter responsibilities, not simulated by this transport seam.
type verificationWork struct {
	calls  int
	last   password.VerificationRequest
	result password.VerificationResult
	err    error
	cancel context.CancelFunc
}

func httpBody(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
func (w *verificationWork) Verify(ctx context.Context, r password.VerificationRequest) (password.VerificationResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded verification")
	}
	w.calls++
	w.last = r
	if w.cancel != nil {
		w.cancel()
	}
	return w.result, w.err
}
func (*verificationWork) Recover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (password.VerificationResult, error) {
	panic("verification must not recover or retry")
}

func newVerification(t *testing.T) (*changeFixture, passwordhttp.BearerVerificationConfig, *verificationWork) {
	t.Helper()
	f := newChange(t, session.CredentialBearer)
	rate, err := identityhttp.NewPasswordVerificationRateLimiter(identityhttp.PasswordVerificationRateConfig{Shared: f.rate, Namespace: "password-verify-test", Key: [32]byte{1}, Now: f.clock.Now, MaximumDuration: f.config.MaximumDuration})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	command, err := identity.ParseCommandID("AQEBAQEBAQEBAQEBAQEBAQ")
	if err != nil {
		t.Fatal(err)
	}
	w := &verificationWork{result: password.VerificationResult{Proof: f.work.proof, CommandID: command, Outcome: identity.CommitOutcomeCommitted}}
	w.result.Proof.Proof.ID = auth.ProofID(w.result.CommandID)
	c := passwordhttp.BearerVerificationConfig{Network: f.config.Network, Sessions: f.config.Sessions, Verification: w, Rate: rate, PolicyRevision: f.config.PolicyRevision, Now: f.clock.Now, MaximumDuration: f.config.MaximumDuration}
	return f, c, w
}
func verificationRequest(f *changeFixture) *http.Request {
	r := changeRequest(f)
	r.URL.Path = "/v1/password/verify"
	r.RequestURI = r.URL.RequestURI()
	r.Header.Del("Idempotency-Key")
	body := `{"password":"synthetic-current-password","purpose":"identity.password.verify","action":"identity.password.change","audience":"identity-service"}`
	r.Body = httpBody(body)
	r.ContentLength = int64(len(body))
	return r
}
func serveVerification(t *testing.T, c passwordhttp.BearerVerificationConfig, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := passwordhttp.NewBearerVerificationHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Header().Get("Cache-Control") != "no-store" || out.Header().Get("Content-Type") != "application/json" || out.Header().Get("X-Content-Type-Options") != "nosniff" || out.Header().Get("Set-Cookie") != "" || out.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("unsafe verification response")
	}
	return out
}
func TestBearerVerificationConservesCustodyAndProjectsOriginalProof(t *testing.T) {
	f, c, work := newVerification(t)
	r := verificationRequest(f)
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "ambient-cookie-ignored"})
	w := serveVerification(t, c, r)
	if w.Code != 200 || work.calls != 1 || f.reader.calls != 1 || f.rate.calls != 1 {
		t.Fatalf("status=%d work=%d read=%d rate=%d", w.Code, work.calls, f.reader.calls, f.rate.calls)
	}
	if work.last.Session.Token() != f.wire || work.last.TenantID != "tenant-a" || work.last.Caller.Request.Subject.ID != "user-a" || work.last.Caller.Request.Action != "identity.password.verify" || work.last.Target.Action != "identity.password.change" || work.last.Network != "198.51.100.7" || work.last.Password.Len() != 0 {
		t.Fatal("custody or cleanup lost")
	}
	var out passwordhttp.VerificationResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Verified || out.Proof == nil || out.Proof.ProofID != string(work.result.Proof.Proof.ID) || out.Proof.ExpiresAt != work.result.Proof.Proof.ExpiresAt || out.CommandID != work.result.CommandID || out.CommitOutcome != "committed" {
		t.Fatal("original proof projection lost")
	}
	for _, forbidden := range []string{f.wire, "synthetic-current-password", "session-a", "user-a", "Signature", "credential"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatal("sensitive response field")
		}
	}
}
func TestBearerVerificationRejectsAlternativeInputsBeforeOwners(t *testing.T) {
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") },
		func(r *http.Request) { r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43)) },
		func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "cookie-is-not-bearer"})
		},
		func(r *http.Request) { r.Header.Add("Authorization", r.Header.Get("Authorization")) },
		func(r *http.Request) { r.URL.RawQuery = "userID=other" },
		func(r *http.Request) {
			r.Body = httpBody(`{"password":"x","purpose":"p","action":"a","audience":"u","userID":"other"}`)
			r.ContentLength = -1
		},
		func(r *http.Request) {
			r.Body = httpBody(`{"password":"x","password":"y","purpose":"p","action":"a","audience":"u"}`)
			r.ContentLength = -1
		},
	} {
		f, c, work := newVerification(t)
		r := verificationRequest(f)
		change(r)
		if w := serveVerification(t, c, r); w.Code != 400 || work.calls != 0 || f.reader.calls != 0 || f.rate.calls != 0 {
			t.Fatal("alternative admitted", w.Code)
		}
	}
}
func TestBearerVerificationDenialUnknownAndCancellationDoNotDeliverProof(t *testing.T) {
	for _, outcome := range []identity.CommitOutcome{identity.CommitOutcomeCommitted, identity.CommitOutcomeUnknown, identity.CommitOutcomeNotCommitted} {
		f, c, work := newVerification(t)
		work.result.Outcome = outcome
		work.err = identity.UnavailableError{}
		w := serveVerification(t, c, verificationRequest(f))
		var out passwordhttp.VerificationResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Verified || out.Proof != nil || out.CommandID != work.result.CommandID || out.CommitOutcome == "none" || work.last.Password.Len() != 0 {
			t.Fatal("ambiguous original observation or custody lost")
		}
	}
	f, c, work := newVerification(t)
	work.result = password.VerificationResult{}
	if w := serveVerification(t, c, verificationRequest(f)); w.Code != 403 || strings.Contains(w.Body.String(), "proofID") || work.last.Password.Len() != 0 {
		t.Fatal("generic mismatch")
	}
	f, c, work = newVerification(t)
	ctx, cancel := context.WithCancel(context.Background())
	work.cancel = cancel
	w := serveVerification(t, c, verificationRequest(f).WithContext(ctx))
	if w.Code != 503 || strings.Contains(w.Body.String(), "proofID") || !strings.Contains(w.Body.String(), "committed") || work.calls != 1 || work.last.Password.Len() != 0 {
		t.Fatal("canceled successful proof leaked", w.Code)
	}
	if h, err := passwordhttp.NewBearerVerificationHandler(passwordhttp.BearerVerificationConfig{}); h != nil || !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("missing composition accepted")
	}
}

func TestBearerVerificationRejectsForeignStaleAndUncommittedProofs(t *testing.T) {
	for _, change := range []func(*password.VerificationResult){
		func(r *password.VerificationResult) { r.Proof.Proof.Tenant = "foreign-tenant" },
		func(r *password.VerificationResult) { r.Proof.Proof.Subject = "foreign-user" },
		func(r *password.VerificationResult) { r.Proof.Proof.Purpose = "foreign-purpose" },
		func(r *password.VerificationResult) { r.Proof.Proof.Audience = "foreign-audience" },
		func(r *password.VerificationResult) { r.Proof.SessionID = "foreign-session" },
		func(r *password.VerificationResult) { r.Proof.SessionVersion++ },
		func(r *password.VerificationResult) { r.Proof.Action = "foreign-action" },
		func(r *password.VerificationResult) { r.Proof.Proof.Method = "oauth" },
		func(r *password.VerificationResult) { r.Proof.Proof.Assurance = auth.AssuranceMultiFactor },
		func(r *password.VerificationResult) { r.Proof.Proof.IssuedAt = r.Proof.Proof.ExpiresAt },
		func(r *password.VerificationResult) {
			r.Proof.Proof.ExpiresAt = r.Proof.Proof.IssuedAt.Add(16 * time.Minute)
		},
		func(r *password.VerificationResult) { r.Proof.Proof.ID = "BBBBBBBBBBBBBBBBBBBBBB" },
		func(r *password.VerificationResult) { r.Outcome = identity.CommitOutcomeUnknown },
	} {
		f, c, work := newVerification(t)
		change(&work.result)
		w := serveVerification(t, c, verificationRequest(f))
		var out passwordhttp.VerificationResponse
		if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Verified || out.Proof != nil || out.CommandID != work.result.CommandID || work.calls != 1 {
			t.Fatal("foreign/stale/uncommitted proof delivered", w.Code)
		}
	}
}

func TestBearerVerificationMiddlewareCannotRefreshOriginalValidityOrOutputCookies(t *testing.T) {
	f, c, work := newVerification(t)
	h, err := passwordhttp.NewBearerVerificationHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "expire", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, ok := identityhttp.PipelineValue[passwordhttp.VerificationState](r)
			if !ok {
				t.Fatal("missing authenticated typed state")
			}
			if _, user, ok := s.Principal(); !ok || user != "user-a" {
				t.Fatal("wrong principal")
			}
			f.clock.now = f.clock.now.Add(20 * time.Second)
			next.ServeHTTP(w, r)
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, verificationRequest(f))
	if w.Code != 503 || work.calls != 0 || f.reader.calls != 1 || f.rate.calls != 1 {
		t.Fatal("expired original refreshed or bypassed", w.Code)
	}
	f, c, work = newVerification(t)
	h, err = passwordhttp.NewBearerVerificationHandlerWithMiddleware(c, []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "short-circuit", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Set-Cookie", "synthetic-forbidden-cookie")
			w.Header().Set("X-CSRF-Token", "synthetic-forbidden-csrf")
			w.Header().Set("Trailer", "X-Secret")
			w.WriteHeader(403)
		})
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, verificationRequest(f))
	if w.Code != 403 || work.calls != 0 || w.Result().Header.Get("Set-Cookie") != "" || w.Result().Header.Get("X-CSRF-Token") != "" || w.Result().Header.Get("Trailer") != "" || w.Result().Header.Get("Cache-Control") != "no-store" {
		t.Fatal("middleware output channel escaped")
	}
}

func TestBearerVerificationConcurrentInvalidRequestsStayIsolated(t *testing.T) {
	f, c, work := newVerification(t)
	h, err := passwordhttp.NewBearerVerificationHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	statuses := make(chan int, 32)
	for range 32 {
		r := verificationRequest(f)
		r.Header.Del("Authorization")
		group.Go(func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); statuses <- w.Code })
	}
	group.Wait()
	close(statuses)
	for status := range statuses {
		if status != 400 {
			t.Fatal("invalid request escaped", status)
		}
	}
	if work.calls != 0 || f.reader.calls != 0 || f.rate.calls != 0 {
		t.Fatal("invalid concurrent requests reached owners")
	}
}
