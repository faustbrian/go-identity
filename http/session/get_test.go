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

	auth "github.com/faustbrian/go-authentication/v2"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

type clock func() time.Time

func (c clock) Now() time.Time { return c() }

type reader func(context.Context, session.SessionLookup) (session.SessionObservation, error)

func (r reader) ObserveSession(c context.Context, l session.SessionLookup) (session.SessionObservation, error) {
	return r(c, l)
}

type shared struct{ *memory.Store }

func (*shared) Name() string { return "test-shared" }
func (s *shared) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return s.Store.AdmitStrict(ctx, r)
}

type fixture struct {
	config      sessionhttp.GetConfig
	wire        string
	observation session.SessionObservation
	calls       atomic.Int32
	fail        atomic.Bool
}

func newFixture(t *testing.T, mode session.CredentialKind) *fixture {
	t.Helper()
	now := time.Date(2026, 10, 8, 21, 0, 0, 0, time.UTC)
	f := &fixture{}
	// Generated ephemeral credential; never retained in test artifacts or output.
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
	spec := session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: now.Add(-2 * time.Minute), LastActivityAt: now.Add(-2 * time.Minute), Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-3 * time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}}
	record, err := session.NewSession(spec)
	if err != nil {
		t.Fatal(err)
	}
	f.observation = session.SessionObservation{Session: record, Current: authority, Active: true, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}
	service, err := session.NewSessionService(reader(func(ctx context.Context, l session.SessionLookup) (session.SessionObservation, error) {
		f.calls.Add(1)
		if _, ok := ctx.Deadline(); !ok {
			t.Error("owner call is unbounded")
		}
		if l.TenantID != "tenant-a" {
			t.Error("unmapped tenant reached owner")
		}
		if f.fail.Load() {
			return session.SessionObservation{}, errors.New("private backend diagnostic")
		}
		return f.observation, nil
	}), session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: clock(func() time.Time { return now }), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := memory.New(memory.Options{MaxKeys: 1024, Shards: 1})
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: &shared{store}, Namespace: "session-get", Now: func() time.Time { return now }, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second, EmergencyMaximumKeys: 1024})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	cookie, _ := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_session", SameSite: http.SameSiteLaxMode})
	f.config = sessionhttp.GetConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Sessions: service, Rate: rate, Transport: mode, Cookie: cookie, Now: func() time.Time { return now }, MaximumDuration: 2 * time.Second}
	return f
}

func request(f *fixture, credential bool) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/session/get", nil)
	r.Host = "tenant.example"
	r.RemoteAddr = "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	if credential {
		if f.config.Transport == session.CredentialBearer {
			r.Header.Set("Authorization", "Bearer "+f.wire)
		} else {
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: f.wire})
		}
	}
	return r
}

func serve(t *testing.T, f *fixture, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	h, err := sessionhttp.NewGetHandler(f.config)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" || len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("session read changed transport or enabled caching")
	}
	return w
}

func TestGetHTTPUsesRealOwnerAndSafeProjection(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newFixture(t, mode)
		before := f.observation
		w := serve(t, f, request(f, true))
		if w.Code != 200 {
			t.Fatalf("status=%d", w.Code)
		}
		var got struct {
			Authenticated bool `json:"authenticated"`
			Principal     struct{ TenantID, UserID string }
			Session       struct {
				ID                           string
				ExpiresAt, AbsoluteExpiresAt time.Time
			}
			NeedsRefresh bool `json:"needsRefresh"`
		}
		if json.Unmarshal(w.Body.Bytes(), &got) != nil || !got.Authenticated || !got.NeedsRefresh || got.Principal.UserID != "user-a" || got.Principal.TenantID != "tenant-a" || got.Session.ID != "session-a" {
			t.Fatal("safe session/principal projection missing")
		}
		spec, _ := before.Session.Bindings()
		lifetime, _ := before.Session.Lifetime(f.config.Now())
		if !got.Session.ExpiresAt.Equal(lifetime.ExpiresAt) || !got.Session.AbsoluteExpiresAt.Equal(spec.IssuedAt.Add(time.Hour)) {
			t.Fatal("original expiry metadata lost or renewed")
		}
		for _, private := range []string{f.wire, "lookup", "digest", "authority", "credentialID", "proof", "family-a"} {
			if strings.Contains(w.Body.String(), private) {
				t.Fatal("private session state disclosed")
			}
		}
		if f.observation != before {
			t.Fatal("GET changed backing session state")
		}
		w = serve(t, f, request(f, false))
		if w.Code != 200 || w.Body.String() != "{\"authenticated\":false,\"needsRefresh\":false}\n" {
			t.Fatal("absent credential not enumeration safe")
		}
	}
}

func TestGetHTTPRejectsAmbiguityBeforeOwner(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		status int
	}{
		{"duplicate-cookie", func(r *http.Request) { r.Header.Add("Cookie", r.Header.Get("Cookie")) }, 400},
		{"cookie-bearer-mix", func(r *http.Request) { r.Header.Set("Authorization", "Bearer unused") }, 400},
		{"retry-key", func(r *http.Request) { r.Header.Set("Idempotency-Key", "key") }, 400},
		{"tenant-query", func(r *http.Request) { r.URL.RawQuery = "tenant_id=other"; r.RequestURI += "?tenant_id=other" }, 400},
		{"unknown-host", func(r *http.Request) { r.Host = "unknown.example" }, 421},
		{"body", func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 }, 400},
		{"plaintext", func(r *http.Request) { r.TLS = nil }, 400},
		{"wrong-method", func(r *http.Request) { r.Method = http.MethodPost }, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, session.CredentialCookie)
			r := request(f, true)
			tc.mutate(r)
			w := serve(t, f, r)
			if w.Code != tc.status || f.calls.Load() != 0 {
				t.Fatalf("unexpected denial status=%d owner calls=%d", w.Code, f.calls.Load())
			}
		})
	}
	f := newFixture(t, session.CredentialBearer)
	r := request(f, false)
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: f.wire})
	if w := serve(t, f, r); w.Code != 200 || strings.Contains(w.Body.String(), "user-a") || f.calls.Load() != 0 {
		t.Fatal("bearer mode fell back to cookie")
	}
	r = request(f, true)
	r.Header.Add("authorization", "Bearer "+f.wire)
	if w := serve(t, f, r); w.Code != 400 || f.calls.Load() != 0 {
		t.Fatal("duplicate authorization reached owner")
	}
}

func TestGetHTTPRateAndOutageDenials(t *testing.T) {
	f := newFixture(t, session.CredentialCookie)
	for i := 0; i < 100; i++ {
		if w := serve(t, f, request(f, false)); w.Code != 200 {
			t.Fatal("early rate denial")
		}
	}
	if w := serve(t, f, request(f, false)); w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("safe rate not enforced")
	}
	f = newFixture(t, session.CredentialCookie)
	f.fail.Store(true)
	if w := serve(t, f, request(f, true)); w.Code != 503 || strings.Contains(w.Body.String(), "private") {
		t.Fatal("owner outage leaked or authenticated")
	}
	f = newFixture(t, session.CredentialCookie)
	r := request(f, true)
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	r = r.WithContext(ctx)
	if w := serve(t, f, r); w.Code != 503 || f.calls.Load() != 0 {
		t.Fatal("cancelled request reached owner")
	}
}

func TestGetHTTPCookieCardinalityAndByteBounds(t *testing.T) {
	for _, count := range []int{32, 33} {
		f := newFixture(t, session.CredentialCookie)
		r := request(f, true)
		for i := 1; i < count; i++ {
			r.Header.Set("Cookie", r.Header.Get("Cookie")+"; other=value")
		}
		w := serve(t, f, r)
		if count == 32 && (w.Code != 200 || f.calls.Load() != 1) || count == 33 && (w.Code != 400 || f.calls.Load() != 0) {
			t.Fatal("cookie cardinality bound wrong")
		}
	}
	for _, size := range []int{16384, 16385} {
		f := newFixture(t, session.CredentialCookie)
		r := request(f, true)
		prefix := r.Header.Get("Cookie") + "; extra="
		r.Header.Set("Cookie", prefix+strings.Repeat("x", size-len(prefix)))
		w := serve(t, f, r)
		if size == 16384 && (w.Code != 200 || f.calls.Load() != 1) || size == 16385 && (w.Code != 400 || f.calls.Load() != 0) {
			t.Fatal("cookie byte bound wrong")
		}
	}
}

func TestSessionCookieTransportNeverNormalizesCredentialValues(t *testing.T) {
	for _, suffix := range []string{" ", "\t", " ; other=safe", "\t; other=safe", "; other=bad ", "; other=bad\t"} {
		t.Run("read", func(t *testing.T) {
			f := newFixture(t, session.CredentialCookie)
			r := request(f, true)
			r.Header.Set("Cookie", r.Header.Get("Cookie")+suffix)
			if w := serve(t, f, r); w.Code != 400 || f.calls.Load() != 0 {
				t.Fatal("malformed cookie reached session reader")
			}
		})
		t.Run("signout", func(t *testing.T) {
			f := newLogout(t, session.CredentialCookie)
			r := logoutRequest(f, true)
			r.Header.Set("Cookie", r.Header.Get("Cookie")+suffix)
			if w := logoutServe(t, f, r); w.Code != 400 || f.calls.Load() != 0 || f.executions != 0 || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("malformed cookie reached session owner or cleared transport")
			}
		})
	}
}

func TestGetHTTPDoesNotRenewEvidenceAfterRateWork(t *testing.T) {
	f := newFixture(t, session.CredentialCookie)
	now := f.config.Now()
	var calls atomic.Int32
	f.config.Now = func() time.Time {
		if calls.Add(1) > 1 {
			return now.Add(20 * time.Second)
		}
		return now
	}
	if w := serve(t, f, request(f, true)); w.Code != 503 || strings.Contains(w.Body.String(), "user-a") {
		t.Fatal("expired owner custody escaped handler")
	}
}

func TestGetHTTPConstructorDeniesMissingComposition(t *testing.T) {
	for _, change := range []func(*sessionhttp.GetConfig){
		func(c *sessionhttp.GetConfig) { c.Sessions = nil }, func(c *sessionhttp.GetConfig) { c.Rate = nil },
		func(c *sessionhttp.GetConfig) { c.Now = nil }, func(c *sessionhttp.GetConfig) { c.Transport = 0 },
		func(c *sessionhttp.GetConfig) { c.Cookie = session.CookiePolicy{} }, func(c *sessionhttp.GetConfig) { c.MaximumDuration = 0 },
		func(c *sessionhttp.GetConfig) { c.Network.TenantHosts = nil },
	} {
		f := newFixture(t, session.CredentialCookie)
		change(&f.config)
		if h, err := sessionhttp.NewGetHandler(f.config); err == nil || h != nil {
			t.Fatal("invalid selected composition accepted")
		}
	}
}
