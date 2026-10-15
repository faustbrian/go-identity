package passwordhttp_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
	primitive "github.com/faustbrian/go-password/v2"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

type testClock struct{ now time.Time }

func (c *testClock) Now() time.Time { return c.now }

type observationReader struct {
	observation session.SessionObservation
	calls       int
}

func (r *observationReader) ObserveSession(ctx context.Context, _ session.SessionLookup) (session.SessionObservation, error) {
	r.calls++
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded read")
	}
	return r.observation, nil
}

type atomicOwner struct {
	ratelimit.StrictBackend
	calls   int
	last    ratelimit.AtomicBatchRequest
	fail    bool
	limited bool
}

func (*atomicOwner) Name() string { return "test-atomic" }
func (b *atomicOwner) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	b.calls++
	b.last = r
	if b.fail {
		return ratelimit.AtomicBatchDecision{}, ratelimit.UnknownOutcome(nil)
	}
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true}
	for _, v := range r.Requests {
		out.Decisions = append(out.Decisions, ratelimit.Decision{Allowed: true, Limit: v.Policy.Limit(), Remaining: v.Policy.Limit() - 1, Reset: v.Now.Add(v.Policy.Period()), Reason: ratelimit.ReasonAllowed})
	}
	if b.limited {
		out.Allowed = false
		for i := range out.Decisions {
			out.Decisions[i].Allowed, out.Decisions[i].Remaining, out.Decisions[i].Reason = false, 0, ratelimit.ReasonLimited
			out.Decisions[i].RetryAfter = time.Second
		}
		return out, ratelimit.ErrRejected
	}
	return out, nil
}

// These doubles occupy native workflow/proof source ports, not simulated SQL
// or password hashing. This suite proves transport conservation only.
type workflow struct {
	calls, proofReads int
	last              password.ChangeRequest
	csrf              session.CSRFToken
	proof             auth.ReauthenticationProof
	result            password.ChangeResult
	err               error
	proofErr          error
	secret            primitive.Secret
	cancel            context.CancelFunc
}

func (w *workflow) Reauthentication(ctx context.Context, id auth.ProofID) (auth.SignedReauthenticationRecord, error) {
	w.proofReads++
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded proof lookup")
	}
	if w.proofErr != nil {
		return auth.SignedReauthenticationRecord{}, w.proofErr
	}
	if id != w.proof.Proof.ID {
		return auth.SignedReauthenticationRecord{}, auth.ErrInvalidProof
	}
	return auth.SignedReauthenticationRecord{Proof: w.proof}, nil
}
func (w *workflow) Change(ctx context.Context, r password.ChangeRequest) (password.ChangeResult, error) {
	w.calls++
	w.last = r
	w.secret = r.Password
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded mutation")
	}
	if w.cancel != nil {
		w.cancel()
	}
	return w.result, w.err
}
func (w *workflow) Recover(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (password.ChangeResult, error) {
	return password.ChangeResult{}, errors.New("not used")
}

type cookieWorkflow struct{ *workflow }

func (w cookieWorkflow) Change(ctx context.Context, r password.CookieChangeRequest) (password.ChangeResult, error) {
	w.csrf = r.CSRFToken
	return w.workflow.Change(ctx, r.Request)
}

type changeFixture struct {
	config passwordhttp.ChangeConfig
	clock  *testClock
	reader *observationReader
	rate   *atomicOwner
	work   *workflow
	wire   string
}

func newChange(t *testing.T, mode session.CredentialKind) *changeFixture {
	t.Helper()
	now := time.Unix(1800000000, 0)
	f := &changeFixture{clock: &testClock{now: now}, reader: &observationReader{}, rate: &atomicOwner{}, work: &workflow{}}
	token, _ := session.NewToken(32)
	f.wire, _ = token.Reveal()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(key, "tenant-a")
	b := func(s string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: s, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b("global"), Tenant: b("tenant"), User: b("user"), Identifier: b("identifier"), Credential: b("credential"), SessionFamily: b("family"), Session: b("session"), Authorization: b("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	proof := auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: now.Add(-time.Minute), LastActivityAt: now.Add(-time.Minute), Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: proof, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	f.reader.observation = session.SessionObservation{Session: record, Current: authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}
	sessions, err := session.NewSessionService(f.reader, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: f.clock, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: f.rate, Namespace: "password-test", Key: [32]byte{1}, Now: f.clock.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	f.config = passwordhttp.ChangeConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Sessions: sessions, Proofs: f.work, Rate: rate, Transport: mode, Cookie: cookie, PolicyRevision: 1, Now: f.clock.Now, MaximumDuration: 2 * time.Second}
	if mode == session.CredentialCookie {
		f.config.CookieChange = cookieWorkflow{f.work}
		f.config.TrustedOrigins = []identityhttp.Origin{"https://tenant.example"}
	} else {
		f.config.BearerChange = f.work
	}
	proof.Purpose = "identity.password.verify"
	f.work.proof = auth.ReauthenticationProof{Proof: proof, SessionID: "session-a", SessionVersion: 1, Action: "identity.password.change"}
	f.work.result = password.ChangeResult{CommandID: "abcdefghijklmnopqrstuv", Outcome: identity.CommitOutcomeCommitted, CredentialVersion: 2, AuthorityInvalidated: true}
	return f
}
func changeRequest(f *changeFixture) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/password/change", strings.NewReader(`{"proofID":"abcdefghijklmnopqrstuv","newPassword":"synthetic-new-password"}`))
	r.Host = "tenant.example"
	r.RemoteAddr = "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "original-byte-key")
	if f.config.Transport == session.CredentialCookie {
		r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: f.wire})
		r.Header.Set("Origin", "https://tenant.example")
		r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43))
	} else {
		r.Header.Set("Authorization", "Bearer "+f.wire)
	}
	return r
}
func serveChange(t *testing.T, f *changeFixture, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := passwordhttp.NewChangeHandler(f.config)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Content-Type") != "application/json" || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("unsafe response policy")
	}
	return w
}

func TestPasswordChangeConservesOriginalCustody(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newChange(t, mode)
		w := serveChange(t, f, changeRequest(f))
		if w.Code != 200 || f.work.calls != 1 || f.work.proofReads != 1 || f.reader.calls != 1 || f.rate.calls != 1 {
			t.Fatalf("status=%d reads=%d proof=%d rate=%d mutation=%d", w.Code, f.reader.calls, f.work.proofReads, f.rate.calls, f.work.calls)
		}
		if f.work.last.TenantID != "tenant-a" || f.work.last.Session.Token() != f.wire || f.work.last.Proof != f.work.proof || f.work.last.Caller.Request.Subject.ID != "user-a" || f.work.last.Network != "198.51.100.7" || f.work.last.Password.Len() != 0 {
			t.Fatal("original custody/cleanup lost")
		}
		key, _ := identity.NewIdempotencyKey([]byte("original-byte-key"))
		expected, _ := key.Digest([32]byte{2})
		actual, _ := f.work.last.IdempotencyKey.Digest([32]byte{2})
		if actual != expected {
			t.Fatal("key bytes changed")
		}
		var out passwordhttp.ChangeResponse
		if json.Unmarshal(w.Body.Bytes(), &out) != nil || !out.Changed || out.CredentialVersion != 2 || out.Recovery == nil || out.Recovery.RecordID != "password-a" {
			t.Fatal("original result lost")
		}
	}
}

func TestPasswordChangeRejectsMalformedBeforeOwners(t *testing.T) {
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Add("Idempotency-Key", "same") }, func(r *http.Request) { r.Header.Del("Idempotency-Key") }, func(r *http.Request) { r.URL.RawQuery = "idempotencyKey=other" }, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }, func(r *http.Request) { r.Header.Set("Authorization", "Bearer mixed") }, func(r *http.Request) { r.Header.Add("X-CSRF-Token", strings.Repeat("A", 43)) }} {
		f := newChange(t, session.CredentialCookie)
		r := changeRequest(f)
		change(r)
		w := serveChange(t, f, r)
		if w.Code < 400 || f.work.calls != 0 || f.reader.calls != 0 || f.rate.calls != 0 {
			t.Fatal("malformed request reached owner")
		}
	}
}

func TestPasswordChangePreservesUnknownAndDeniesContradictorySuccess(t *testing.T) {
	f := newChange(t, session.CredentialBearer)
	f.work.result.Outcome = identity.CommitOutcomeUnknown
	f.work.err = identity.UnknownCommitError{CommandID: f.work.result.CommandID}
	w := serveChange(t, f, changeRequest(f))
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"commitOutcome":"unknown"`) || strings.Contains(w.Body.String(), `"changed":true`) {
		t.Fatal("unknown upgraded or discarded")
	}
	f = newChange(t, session.CredentialBearer)
	f.work.result.CommandID = ""
	w = serveChange(t, f, changeRequest(f))
	if w.Code != 503 {
		t.Fatal("committed success without original command accepted")
	}
}

func TestPasswordChangeMapsNativeDeniedAndBusyOutcomes(t *testing.T) {
	for _, row := range []struct {
		err     error
		outcome identity.CommitOutcome
		status  int
		code    string
	}{
		{identity.ForbiddenError{}, identity.CommitOutcomeInvalid, 403, "denied"},
		{identity.ConflictError{}, identity.CommitOutcomeConflict, 409, "conflict"},
		{identity.InProgressError{RetryAfter: 1500 * time.Millisecond}, identity.CommitOutcomeInProgress, 409, "in_progress"},
	} {
		f := newChange(t, session.CredentialBearer)
		f.work.err = row.err
		f.work.result.Outcome = row.outcome
		if row.code == "conflict" {
			// Native prepared-key conflicts occur before a command exists.
			f.work.result.CommandID = ""
		}
		w := serveChange(t, f, changeRequest(f))
		if w.Code != row.status || !strings.Contains(w.Body.String(), `"error":"`+row.code+`"`) {
			t.Fatalf("native classification status=%d", w.Code)
		}
		if row.code == "in_progress" && w.Header().Get("Retry-After") != "2" {
			t.Fatal("busy retry missing")
		}
		if row.code == "conflict" {
			var out passwordhttp.ChangeResponse
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommandID != "" || out.Recovery != nil {
				t.Fatal("pre-command conflict manufactured recovery identity")
			}
		}
	}
}

func TestPasswordChangeAttemptObserverExcludesPreliminaryProofFailure(t *testing.T) {
	f := newChange(t, session.CredentialBearer)
	f.work.proofErr = password.ErrPasswordWork
	observed := false
	hooks := []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "observe", Phase: identityhttp.MiddlewareAfterHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
			s, ok := identityhttp.PipelineValue[passwordhttp.ChangeState](r)
			out, attempted := s.Attempt()
			observed = true
			if !ok || attempted || out.CommitOutcome != "none" || out.CommandID != "" || out.Recovery != nil {
				t.Error("preliminary failure became native attempt")
			}
		})
	}}}}
	h, err := passwordhttp.NewChangeHandlerWithMiddleware(f.config, hooks)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, changeRequest(f))
	if w.Code != 503 || !observed || f.work.calls != 0 {
		t.Fatal("observer missed preliminary failure")
	}
}

func TestPasswordChangeDistinguishesMissingProofFromUnavailableSource(t *testing.T) {
	for _, row := range []struct {
		name   string
		err    error
		status int
	}{
		{"missing", auth.ErrInvalidProof, 403},
		{"store", password.ErrPasswordWork, 503},
		{"canceled", context.Canceled, 503},
		{"deadline", context.DeadlineExceeded, 503},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newChange(t, session.CredentialBearer)
			f.work.proofErr = row.err
			w := serveChange(t, f, changeRequest(f))
			if w.Code != row.status || f.work.calls != 0 || !strings.Contains(w.Body.String(), `"commitOutcome":"none"`) {
				t.Fatalf("proof source classification status=%d mutation=%d", w.Code, f.work.calls)
			}
		})
	}
}

func TestPasswordChangeHonorsOriginalValidityAndProtectsHookResponses(t *testing.T) {
	f := newChange(t, session.CredentialBearer)
	hooks := []identityhttp.MiddlewareDescriptor{{Owner: "identity/password", Middleware: identityhttp.Middleware{Name: "expire", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s, ok := identityhttp.PipelineValue[passwordhttp.ChangeState](r)
			tenant, user, admitted := s.Principal()
			if !ok || !admitted || tenant != "tenant-a" || user != "user-a" {
				t.Error("missing owner state")
			}
			f.clock.now = f.clock.now.Add(21 * time.Second)
			next.ServeHTTP(w, r)
			w.Header()["set-cookie"] = []string{"forged=credential"}
			w.Header()["Trailer:X-CSRF-Token"] = []string{"forged"}
		})
	}}}}
	h, err := passwordhttp.NewChangeHandlerWithMiddleware(f.config, hooks)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, changeRequest(f))
	if w.Code != 503 || f.work.calls != 0 || f.work.proofReads != 0 || w.Header().Get("Set-Cookie") != "" || len(w.Header()["set-cookie"]) != 0 || len(w.Header()["Trailer:X-CSRF-Token"]) != 0 {
		t.Fatal("expired authority or hook credential escape")
	}
}

func TestPasswordChangeCanceledCommittedOutcomeRemainsHistorical(t *testing.T) {
	f := newChange(t, session.CredentialBearer)
	r := changeRequest(f)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	f.work.cancel = cancel
	w := serveChange(t, f, r)
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"commitOutcome":"committed"`) || strings.Contains(w.Body.String(), `"changed":true`) || f.work.secret.Len() != 0 {
		t.Fatal("cancellation became rollback or success")
	}
}
