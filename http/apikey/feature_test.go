package apikeyhttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/apikey"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

// These ports isolate wire admission only. The native PostgreSQL consumer,
// rather than these projections, must prove issuance and current authority.
type fixtureClock struct{ now time.Time }

func (c *fixtureClock) Now() time.Time { return c.now }

type fixtureSessions struct {
	value session.SessionObservation
	calls int
}

func (s *fixtureSessions) ObserveSession(context.Context, session.SessionLookup) (session.SessionObservation, error) {
	s.calls++
	return s.value, nil
}

type fixtureRate struct {
	ratelimit.StrictBackend
	calls int
	mode  int
}

func (*fixtureRate) Name() string { return "wire-admission-test" }
func (b *fixtureRate) AdmitAtomicStrict(_ context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	b.calls++
	if b.mode == 2 {
		return ratelimit.AtomicBatchDecision{}, ratelimit.ErrUnavailable
	}
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: true}
	for _, q := range r.Requests {
		out.Decisions = append(out.Decisions, ratelimit.Decision{Allowed: true, Remaining: q.Policy.Limit() - q.Cost, Limit: q.Policy.Limit(), Reset: q.Now.Add(q.Policy.Period()), Reason: ratelimit.ReasonAllowed})
	}
	if b.mode == 1 {
		out.Allowed = false
		for i := range out.Decisions {
			out.Decisions[i].Allowed = false
			out.Decisions[i].Remaining = 0
			out.Decisions[i].Reason = ratelimit.ReasonLimited
			out.Decisions[i].RetryAfter = 1500 * time.Millisecond
		}
		return out, ratelimit.ErrRejected
	}
	return out, nil
}

type fixtureNative struct {
	calls      int
	create     apikey.CreateRequest
	rotation   apikey.Rotation
	revocation apikey.Revocation
	issued     *apikey.IssuanceResult
	receipt    *identity.CommandResult
	err        error
}

func (s *fixtureNative) Create(_ context.Context, r apikey.CreateRequest) (apikey.IssuanceResult, error) {
	s.calls++
	s.create = r
	if s.issued != nil {
		return *s.issued, s.err
	}
	return apikey.IssuanceResult{}, apikey.ErrDenied
}
func (s *fixtureNative) Rotate(_ context.Context, r apikey.Rotation) (apikey.IssuanceResult, error) {
	s.calls++
	s.rotation = r
	if s.issued != nil {
		return *s.issued, s.err
	}
	return apikey.IssuanceResult{}, apikey.ErrDenied
}
func (s *fixtureNative) Revoke(_ context.Context, r apikey.Revocation) (identity.CommandResult, error) {
	s.calls++
	s.revocation = r
	if s.receipt != nil {
		return *s.receipt, s.err
	}
	return identity.CommandResult{}, apikey.ErrDenied
}

type fixture struct {
	config   FeatureConfig
	native   *fixtureNative
	sessions *fixtureSessions
	rate     *fixtureRate
	token    string
	clock    *fixtureClock
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{native: new(fixtureNative), sessions: new(fixtureSessions), rate: new(fixtureRate), clock: &fixtureClock{time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}}
	token, _ := session.NewToken(32)
	f.token, _ = token.Reveal()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(key, "tenant-a")
	b := func(name string) session.AuthorityBinding {
		return session.AuthorityBinding{ScopeKey: name, Version: 1}
	}
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b("global"), Tenant: b("tenant"), User: b("user"), Identifier: b("identifier"), Credential: b("credential"), SessionFamily: b("family"), Session: b("session"), Authorization: b("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: f.clock.now.Add(-time.Minute), LastActivityAt: f.clock.now.Add(-time.Minute), Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: auth.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: auth.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: f.clock.now.Add(-2 * time.Minute), ExpiresAt: f.clock.now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	f.sessions.value = session.SessionObservation{Session: record, Current: authority, Active: true, ReadStartedAt: f.clock.now, ValidUntil: f.clock.now.Add(20 * time.Second)}
	sessions, err := session.NewSessionService(f.sessions, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: f.clock, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewKeyedSecretRateLimiter(identityhttp.KeyedSecretRateConfig{Shared: f.rate, Namespace: "apikey-wire", Key: [32]byte{1}, Now: f.clock.Now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rate.Close() })
	f.config = FeatureConfig{Config: Config{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 2048, MaximumBodyBytes: 65536, MaximumDecodedBytes: 65536, MaximumFields: 128, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Sessions: sessions, Creator: f.native, Rotator: f.native, Revoker: f.native, SecretRate: rate, Now: f.clock.Now, MaximumDuration: 2 * time.Second}, Create: true, Rotate: true, Revoke: true}
	return f
}
func (f fixture) request(action, body string) *http.Request {
	r := httptest.NewRequest("POST", "/v1/apikey/"+action, strings.NewReader(body))
	r.Host = "tenant.example"
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "198.51.100.1:12345"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.token)
	r.Header.Set("Idempotency-Key", "original-apikey-command")
	return r
}
func fixtureHandler(t *testing.T, f fixture) http.Handler {
	t.Helper()
	feature, err := NewFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestManagementMapsOnlyTrustedBearerAndNetwork(t *testing.T) {
	for _, action := range []string{"create", "rotate", "delete"} {
		t.Run(action, func(t *testing.T) {
			f := newFixture(t)
			h := fixtureHandler(t, f)
			body := `{"keyID":"key-a","expectedVersion":1}`
			if action == "create" {
				body = `{"name":"consumer key","permissions":["read"],"expiresAt":"2026-10-29T12:00:00Z"}`
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, f.request(action, body))
			if w.Code != 403 || f.native.calls != 1 || f.rate.calls != 1 || f.sessions.calls != 1 || w.Body.String() != "{\"error\":\"forbidden\"}\n" {
				t.Fatal("wire boundary did not reach exactly one native denial", w.Code, f.native.calls, f.rate.calls, f.sessions.calls)
			}
			if w.Header().Get("Cache-Control") != "no-store" || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("management response changed credential/cache custody")
			}
			switch action {
			case "create":
				if f.native.create.Validate() != nil || f.native.create.Network != "198.51.100.1" || f.native.create.Authentication.TenantID != "tenant-a" || f.native.create.Authentication.Bearer.Token() != f.token || f.native.create.Name != "consumer key" {
					t.Fatal("create input lost trusted mapping")
				}
			case "rotate":
				if f.native.rotation.Validate() != nil || f.native.rotation.KeyID != "key-a" || f.native.rotation.ExpectedVersion != 1 {
					t.Fatal("rotation input lost native keyed custody")
				}
			case "delete":
				if f.native.revocation.Validate() != nil || f.native.revocation.KeyID != "key-a" {
					t.Fatal("revocation input lost native keyed custody")
				}
			}
		})
	}
}

func TestManagementRejectsAlternateAuthorityBeforeDomain(t *testing.T) {
	for name, change := range map[string]func(*http.Request){
		"missing-bearer":   func(r *http.Request) { r.Header.Del("Authorization"); r.Header.Set("Cookie", "session=ambient") },
		"duplicate-bearer": func(r *http.Request) { r.Header.Add("authorization", r.Header.Get("Authorization")) },
		"missing-key":      func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate-key":    func(r *http.Request) { r.Header.Add("Idempotency-Key", r.Header.Get("Idempotency-Key")) },
		"empty-body":       func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 0 },
		"query-tenant":     func(r *http.Request) { r.URL.RawQuery = "tenantID=attacker" },
		"unknown-host":     func(r *http.Request) { r.Host = "attacker.example" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			h := fixtureHandler(t, f)
			r := f.request("rotate", `{"keyID":"key-a","expectedVersion":1}`)
			change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || f.native.calls != 0 || f.rate.calls != 0 || f.sessions.calls != 0 {
				t.Fatal("untrusted request reached authority or mutation", w.Code)
			}
		})
	}
	for _, body := range []string{`{"keyID":"key-a","expectedVersion":1,"ownerID":"attacker"}`, `{"keyID":"key-a","expectedVersion":1,"tenantID":"attacker"}`, `{"keyID":"key-a","expectedVersion":1,"network":"127.0.0.1"}`, `{"keyID":"key-a","keyID":"key-b","expectedVersion":1}`, `{"keyID":"key-a","expectedVersion":1e0}`, `{"keyID":"key-a","expectedVersion":18446744073709551615}`} {
		f := newFixture(t)
		h := fixtureHandler(t, f)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, f.request("rotate", body))
		if w.Code != 400 || f.native.calls != 0 || f.sessions.calls != 0 {
			t.Fatal("closed mutation input admitted", w.Code)
		}
	}
}

func TestCreateRequiresAnExplicitArrayIncludingEmptyGrant(t *testing.T) {
	for _, body := range []string{
		`{"name":"empty","expiresAt":"2026-10-29T12:00:00Z"}`,
		`{"name":"empty","permissions":null,"expiresAt":"2026-10-29T12:00:00Z"}`,
	} {
		f := newFixture(t)
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request("create", body))
		if w.Code != 400 || f.native.calls != 0 || f.sessions.calls != 0 {
			t.Fatal("missing/null permission array reached native authority", w.Code)
		}
	}
	f := newFixture(t)
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("create", `{"name":"empty","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`))
	if w.Code != 403 || f.native.calls != 1 || len(f.native.create.Permissions) != 0 {
		t.Fatal("explicit empty native grant was narrowed out of the wire profile", w.Code)
	}
}

func TestCreateAcceptsMaximumEscapedNativeGrant(t *testing.T) {
	f := newFixture(t)
	permissions := make([]string, 64)
	for i := range permissions {
		permissions[i] = fmt.Sprintf("%02d%s", i, strings.Repeat("&", 126))
	}
	body, err := json.Marshal(map[string]any{"name": "maximum", "permissions": permissions, "expiresAt": "2026-10-29T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("create", string(body)))
	if w.Code != 403 || f.native.calls != 1 || len(f.native.create.Permissions) != 64 {
		t.Fatal("transport narrowed a supported native permission ceiling", w.Code)
	}
}

func TestSelectedCreateRequiresUsableNestingWithoutRestrictingMutations(t *testing.T) {
	f := newFixture(t)
	f.config.Network.Limits.MaximumDepth = 1
	if _, err := NewFeature(f.config); err == nil {
		t.Fatal("selected create accepted a limit that rejects every permissions array")
	}
	f.config.Network.Limits.MaximumDepth = 2
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, f.request("create", `{"name":"key","permissions":[],"expiresAt":"2026-10-29T12:00:00Z"}`))
	if w.Code != 403 || f.native.calls != 1 {
		t.Fatal("minimum usable create nesting denied native input", w.Code)
	}
	for _, action := range []string{"rotate", "delete"} {
		f := newFixture(t)
		f.config.Create = false
		f.config.Creator = nil
		f.config.Network.Limits.MaximumDepth = 1
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request(action, `{"keyID":"key-a","expectedVersion":1}`))
		if w.Code != 403 || f.native.calls != 1 {
			t.Fatal("create nesting restriction disabled scalar-only mutation", action, w.Code)
		}
	}
}

func TestHTTPRateDenialAndOutagePreventNativeMutation(t *testing.T) {
	for _, mode := range []int{1, 2} {
		f := newFixture(t)
		f.rate.mode = mode
		w := httptest.NewRecorder()
		fixtureHandler(t, f).ServeHTTP(w, f.request("rotate", `{"keyID":"key-a","expectedVersion":1}`))
		want := 429
		if mode == 2 {
			want = 503
		}
		if w.Code != want || f.native.calls != 0 || f.rate.calls != 1 || f.sessions.calls != 1 {
			t.Fatal("HTTP admission failure reached native mutation", w.Code)
		}
		if mode == 1 && w.Header().Get("Retry-After") != "2" || mode == 2 && w.Header().Get("Retry-After") != "" {
			t.Fatal("HTTP admission lost known/unknown retry distinction")
		}
	}
}
