package otphttp_test

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

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	otphttp "github.com/faustbrian/go-identity/http/otp"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// This explicit test backend exercises the real primitive bucket algorithm;
// production composition still requires the native shared strict backend.
type shared struct{ *memory.Store }

func (*shared) Name() string { return "test-only" }
func (s *shared) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return s.Store.AdmitStrict(ctx, r)
}

type owner struct {
	t                 *testing.T
	sources, attempts int
	sourceErr         error
	result            func(context.Context, otp.SigninRequest) (otp.SigninResult, error)
	backend           *memory.Store
}

func (s *owner) ResolveSigninSource(ctx context.Context, r otp.SigninSourceRequest) (otp.SigninSource, error) {
	s.sources++
	if _, ok := ctx.Deadline(); !ok {
		s.t.Error("unbounded owner")
	}
	if r.Validate() != nil || r.UserID != "" || r.TenantID != "tenant-a" || r.Caller.Request.Action != "identity.otp.signin" {
		s.t.Error("wrong original selection")
	}
	if s.sourceErr != nil {
		return otp.SigninSource{}, s.sourceErr
	}
	d, _ := otp.NewDestinationInput("original@example.invalid")
	return otp.NewSigninSource(otp.SigninSourceBindings{TenantID: r.TenantID, SendCommandID: r.SendCommandID, Channel: otp.ChannelEmail, Destination: d})
}
func (s *owner) Signin(ctx context.Context, r otp.SigninRequest) (otp.SigninResult, error) {
	s.attempts++
	if r.Validate() != nil {
		s.t.Error("invalid native request")
	}
	if s.result != nil {
		return s.result(ctx, r)
	}
	return otp.SigninResult{}, errors.New("private diagnostic original@example.invalid")
}

func issuance(t *testing.T, c otphttp.SigninConfig, r otp.SigninRequest) otp.SigninResult {
	t.Helper()
	now := c.Now()
	command, _ := identity.NewCommandID()
	identifier, _ := identity.ParseIdentifierID("AQEBAQEBAQEBAQEBAQEBAQ")
	token, _ := session.NewToken(32)
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(key, string(r.TenantID))
	b := func(s string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: s, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b("global"), Tenant: b("tenant"), User: b("user"), Identifier: b("identifier"), Credential: b("credential"), SessionFamily: b("family"), Session: b("session"), Authorization: b("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := session.NewOTPAuthentication(session.OTPAuthenticationSpec{CommandID: command, SendCommandID: r.SendCommandID, ChallengeID: "original-challenge", AttemptID: "AQEBAQEBAQEBAQEBAQEBAQ", IdentifierID: identifier, IdentifierKind: identity.IdentifierEmail, IdentifierVersion: 1, VerificationVersion: 1, AuthenticatedAt: now, ValidUntil: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := session.NewCSRFToken()
	csrfKey, _ := session.NewCSRFKey(1, make([]byte, 32))
	state, _ := csrf.Digest(csrfKey, session.CSRFBinding{TenantID: r.TenantID, SessionID: "session-a", SessionVersion: 1})
	record, err := session.NewSessionWithOTPAndCSRF(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: r.TenantID, UserID: "user-a", Audience: c.Audience, Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationOTP}, IssuedAt: now, LastActivityAt: now}, metadata, state)
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := c.SessionCookie.Attributes(remember, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := otp.NewSigninRecovery(otp.SigninRecoveryBindings{SendCommandID: r.SendCommandID, Attempt: otp.AttemptRecoveryIdentity{CommandID: command, TenantID: r.TenantID, AttemptID: "AQEBAQEBAQEBAQEBAQEBAQ", Fingerprint: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI", FingerprintKeyVersion: 1}, ExpectedVersion: 1, DigestKeyVersion: 1, ScopeDigest: [32]byte{1}})
	if err != nil {
		t.Fatal(err)
	}
	return otp.SigninResult{SessionID: "session-a", Issuance: session.IssueResult{CommandID: command, CommitOutcome: identity.CommitOutcomeCommitted, Session: record, Token: token, Cookie: cookie}, CSRFToken: csrf, Recovery: recovery}
}

func TestSigninFreshCommitDeliversOnlySecureCookieAndSynchronizer(t *testing.T) {
	c, s, body := fixture(t)
	var first otp.SigninResult
	s.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) {
		first = issuance(t, c, r)
		return first, nil
	}
	h, err := otphttp.NewSigninHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 200 {
		t.Fatalf("successful native result withheld status=%d", w.Code)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-identity_session" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Domain != "" || cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].MaxAge != 0 {
		t.Fatal("unsafe cookie")
	}
	if _, err := session.ParseToken(cookies[0].Value); err != nil {
		t.Fatal("invalid delivered token")
	}
	if _, err := first.Issuance.Token.Reveal(); err == nil {
		t.Fatal("bearer reveal was not consumed")
	}
	if _, err := session.ParseCSRFToken(w.Header().Get("X-CSRF-Token")); err != nil {
		t.Fatal("missing synchronizer")
	}
	var response otphttp.SigninResponse
	if json.Unmarshal(w.Body.Bytes(), &response) != nil || !response.SignedIn || response.CommitOutcome != "committed" || response.Recovery == nil {
		t.Fatal("lost original correlation")
	}
	if strings.Contains(w.Body.String(), cookies[0].Value) || strings.Contains(w.Body.String(), w.Header().Get("X-CSRF-Token")) {
		t.Fatal("credential in JSON")
	}
}

func TestSigninAmbiguityReplayCancellationNeverDeliver(t *testing.T) {
	for _, mode := range []string{"error", "unknown", "replay", "canceled", "foreign", "bad-cookie", "no-csrf", "panic"} {
		t.Run(mode, func(t *testing.T) {
			c, s, body := fixture(t)
			r := request(body)
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			s.result = func(_ context.Context, request otp.SigninRequest) (otp.SigninResult, error) {
				out := issuance(t, c, request)
				switch mode {
				case "error":
					return out, errors.New("private diagnostic")
				case "unknown":
					out.Issuance.CommitOutcome = identity.CommitOutcomeUnknown
				case "replay":
					out.Issuance.Replayed = true
				case "canceled":
					cancel()
				case "foreign":
					out.SessionID = "foreign"
				case "bad-cookie":
					out.Issuance.Cookie.Domain = "foreign.example"
				case "no-csrf":
					out.CSRFToken = session.CSRFToken{}
				case "panic":
					panic("private panic")
				}
				return out, nil
			}
			h, err := otphttp.NewSigninHandler(c)
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 503 || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("failure delivered credentials")
			}
			var response otphttp.SigninResponse
			if json.Unmarshal(w.Body.Bytes(), &response) != nil || response.SignedIn {
				t.Fatal("unsafe error envelope")
			}
			if mode == "error" && (response.CommitOutcome != "committed" || response.Recovery == nil) {
				t.Fatal("error erased commitment/recovery")
			}
			if mode == "unknown" && (response.CommitOutcome != "unknown" || response.Recovery == nil) {
				t.Fatal("ambiguity erased original correlation")
			}
		})
	}
}
func (*owner) RecoverSignin(context.Context, otp.SigninRecoveryRequest) (otp.SigninResult, error) {
	panic("transport must not retry")
}
func fixture(t *testing.T) (otphttp.SigninConfig, *owner, string) {
	t.Helper()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	store, _ := memory.New(memory.Options{MaxKeys: 1024, Shards: 1})
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: &shared{store}, Namespace: "otp-http", Now: func() time.Time { return now }, IdentifierKey: [32]byte{1}, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	flow, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_flow", SameSite: http.SameSiteLaxMode})
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	s := &owner{t: t, backend: store}
	command, _ := identity.NewCommandID()
	return otphttp.SigninConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Service: s, Source: s, Rate: rate, Origin: "https://tenant.example", FlowCookie: flow, SessionCookie: cookie, ActorID: "public-entry", PolicyRevision: 9, Audience: "identity-service", Now: func() time.Time { return now }, MaximumDuration: time.Second}, s, `{"flowID":"AQEBAQEBAQEBAQEBAQEBAQ","sendCommandID":"` + string(command) + `","code":"123456"}`
}
func request(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/v1/otp/signin", strings.NewReader(body))
	r.Host = "tenant.example"
	r.RemoteAddr = "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://tenant.example")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
	return r
}
func TestSigninOriginalSourceBudgetAndNoRetry(t *testing.T) {
	c, s, body := fixture(t)
	h, err := otphttp.NewSigninHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 11; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(body))
		want := 503
		if i == 10 {
			want = 429
		}
		if w.Code != want || len(w.Header().Values("Set-Cookie")) != 0 || strings.Contains(w.Body.String(), "original@example.invalid") || strings.Contains(w.Body.String(), "private diagnostic") {
			t.Fatalf("unsafe or wrong outcome status=%d", w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable response")
		}
		if i == 10 && w.Header().Get("Retry-After") == "" {
			t.Fatal("missing retry bound")
		}
	}
	if s.attempts != 10 || s.sources != 11 {
		t.Fatal("source budget bypass or automatic retry")
	}
}

func TestSigninSourceRejectionStillRetainsSharedIPBudget(t *testing.T) {
	c, s, body := fixture(t)
	s.sourceErr = errors.New("private custody denial")
	h, err := otphttp.NewSigninHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 21; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(body))
		want := 503
		if i == 20 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("source denial bypassed IP ceiling status=%d at=%d", w.Code, i)
		}
	}
	if s.sources != 20 || s.attempts != 0 {
		t.Fatal("exhausted IP reached source or signin")
	}
}

func TestSigninSharedRateOutageDeniesBeforeSource(t *testing.T) {
	c, s, body := fixture(t)
	s.backend.Close()
	h, err := otphttp.NewSigninHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 503 || s.sources != 0 || s.attempts != 0 || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("backend outage reached native source or delivered credentials")
	}
}

func TestSigninPreparedRecoverySurvivesBeforeIssuance(t *testing.T) {
	c, s, body := fixture(t)
	s.result = func(_ context.Context, r otp.SigninRequest) (otp.SigninResult, error) {
		out := issuance(t, c, r)
		out.SessionID = ""
		out.Issuance = session.IssueResult{}
		out.CSRFToken = session.CSRFToken{}
		return out, errors.New("session preparation failed")
	}
	h, err := otphttp.NewSigninHandler(c)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	var out otphttp.SigninResponse
	if w.Code != 503 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Recovery == nil || out.CommandID == "" || out.Recovery.Attempt.CommandID != out.CommandID || out.CommitOutcome != "none" || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("lost prepared native recovery before issuance")
	}
}
func TestSigninRejectsReplacementAndOriginBeforeOwner(t *testing.T) {
	for _, change := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") },
		func(r *http.Request) { r.Header.Set("Idempotency-Key", "replacement") },
		func(r *http.Request) { r.Header.Set("Authorization", "Bearer replacement") },
		func(r *http.Request) { r.URL.RawQuery = "remember=true" },
		func(r *http.Request) { r.Header.Add("Cookie", "__Host-identity_flow="+strings.Repeat("A", 43)) },
	} {
		c, s, body := fixture(t)
		h, err := otphttp.NewSigninHandler(c)
		if err != nil {
			t.Fatal(err)
		}
		r := request(body)
		change(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code < 400 || s.sources != 0 || s.attempts != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("untrusted override reached owner")
		}
	}
	c, s, body := fixture(t)
	h, _ := otphttp.NewSigninHandler(c)
	body = strings.TrimSuffix(body, "}") + `,"remember":true}`
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 400 || s.sources != 0 {
		t.Fatal("remember override accepted")
	}
}
