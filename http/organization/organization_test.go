package organizationhttp_test

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

	authentication "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	"github.com/faustbrian/go-identity/session"
	organization "github.com/faustbrian/go-organization"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

type testClock func() time.Time

func (c testClock) Now() time.Time { return c() }

type sessionReader func(context.Context, session.SessionLookup) (session.SessionObservation, error)

func (r sessionReader) ObserveSession(ctx context.Context, q session.SessionLookup) (session.SessionObservation, error) {
	return r(ctx, q)
}

type safeBackend struct{ *memory.Store }

func (*safeBackend) Name() string { return "test-only-shared" }
func (b *safeBackend) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return b.Store.AdmitStrict(ctx, r)
}

type atomicBackend struct {
	ratelimit.StrictBackend
	last        ratelimit.AtomicBatchRequest
	calls, mode int
}

func (*atomicBackend) Name() string { return "test-only-atomic" }
func (b *atomicBackend) AdmitAtomicStrict(ctx context.Context, r ratelimit.AtomicBatchRequest) (ratelimit.AtomicBatchDecision, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		panic("unbounded atomic admission")
	}
	b.last, b.calls = r, b.calls+1
	if b.mode == 2 {
		return ratelimit.AtomicBatchDecision{}, ratelimit.UnknownOutcome(nil)
	}
	if b.mode == 3 {
		return ratelimit.AtomicBatchDecision{}, ratelimit.ErrUnavailable
	}
	if b.mode == 4 {
		panic("private rate diagnostic")
	}
	out := ratelimit.AtomicBatchDecision{CommandID: r.CommandID, Allowed: b.mode != 1, Decisions: make([]ratelimit.Decision, len(r.Requests))}
	for i, q := range r.Requests {
		out.Decisions[i] = ratelimit.Decision{Allowed: out.Allowed, Remaining: q.Policy.Limit() - q.Cost, Limit: q.Policy.Limit(), Reset: q.Now.Add(q.Policy.Period()), Reason: ratelimit.ReasonAllowed}
		if b.mode == 1 {
			out.Decisions[i].Remaining = 0
			out.Decisions[i].Reason = ratelimit.ReasonLimited
			out.Decisions[i].RetryAfter = 1500 * time.Millisecond
		}
	}
	if b.mode == 1 {
		return out, ratelimit.ErrRejected
	}
	return out, nil
}

type nativePort struct {
	t              testing.TB
	calls          int
	lastCreate     organization.CreateOperationRequest
	lastAdd        organization.AddMemberOperationRequest
	lastRemove     organization.RemoveMemberOperationRequest
	lastRead       organization.ReadRequest
	network        string
	err            error
	outcome        identity.CommitOutcome
	beforeCall     func()
	changeRead     func(*organization.View)
	changeMutation func(*organization.StoreResult)
}

func (p *nativePort) mutation(ctx context.Context, op organization.Operation, auth organization.Authentication, org organization.ID, user identity.UserID) (organization.StoreResult, error) {
	p.calls++
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("unbounded native operation")
	}
	if p.beforeCall != nil {
		p.beforeCall()
	}
	id, _ := identity.NewCommandID()
	b := identity.CommandBinding{CommandID: id, TenantID: auth.TenantID, UserID: user, ActorID: "user-a", ActorKind: authorization.SubjectUser, RecordID: string(org), OperationID: string(op), SchemaID: op.Descriptor().SchemaID, SchemaVersion: 1, PolicyID: "organization-policy", PolicyVersion: 1, CorrelationID: "original"}
	r := identity.CommandResult{Binding: b, Outcome: p.outcome, Feature: &identity.FeatureReceipt{Operation: op.Descriptor()}}
	if p.outcome == identity.CommitOutcomeCommitted {
		r.AuditEventID = "event"
		before := uint64(0)
		if op == organization.AddMember {
			before = p.lastAdd.OrganizationVersion
		}
		if op == organization.RemoveMember {
			before = p.lastRemove.OrganizationVersion
		}
		r.Feature.BeforeVersion, r.Feature.AfterVersion = before, before+1
	}
	out := organization.StoreResult{Receipt: r, OrganizationID: org, MemberID: user}
	if p.changeMutation != nil {
		p.changeMutation(&out)
	}
	return out, p.err
}
func (p *nativePort) Create(ctx context.Context, r organization.CreateOperationRequest, network string) (organization.StoreResult, error) {
	p.lastCreate, p.network = r, network
	return p.mutation(ctx, organization.Create, r.Authentication, "organization-a", "user-a")
}
func (p *nativePort) AddMember(ctx context.Context, r organization.AddMemberOperationRequest, network string) (organization.StoreResult, error) {
	p.lastAdd, p.network = r, network
	return p.mutation(ctx, organization.AddMember, r.Authentication, r.OrganizationID, r.UserID)
}
func (p *nativePort) RemoveMember(ctx context.Context, r organization.RemoveMemberOperationRequest, network string) (organization.StoreResult, error) {
	p.lastRemove, p.network = r, network
	return p.mutation(ctx, organization.RemoveMember, r.Authentication, r.OrganizationID, r.UserID)
}
func (p *nativePort) read(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	p.calls++
	p.lastRead = r
	if _, ok := ctx.Deadline(); !ok {
		p.t.Fatal("unbounded native read")
	}
	out := organization.View{Organization: organization.Organization{ID: r.OrganizationID, TenantID: r.Authentication.TenantID, Name: "Native organization", Slug: "native-org", Version: 3, Active: true}, Actor: organization.Member{OrganizationID: r.OrganizationID, TenantID: r.Authentication.TenantID, UserID: "user-a", Role: organization.RoleOwner, Version: 1, Active: true}, Members: []organization.Member{{OrganizationID: r.OrganizationID, TenantID: r.Authentication.TenantID, UserID: "user-a", Role: organization.RoleOwner, Version: 1, Active: true}}}
	if p.changeRead != nil {
		p.changeRead(&out)
	}
	return out, p.err
}
func (p *nativePort) Get(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	return p.read(ctx, r)
}
func (p *nativePort) ListMembers(ctx context.Context, r organization.ReadRequest) (organization.View, error) {
	return p.read(ctx, r)
}

type fixture struct {
	c        organizationhttp.Config
	port     *nativePort
	rate     *atomicBackend
	wire     string
	reads    atomic.Int32
	denials  atomic.Int32
	now      time.Time
	inactive bool
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	f := &fixture{now: time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC), rate: new(atomicBackend), port: &nativePort{t: t, outcome: identity.CommitOutcomeCommitted}}
	token, _ := session.NewToken(32)
	f.wire, _ = token.Reveal()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(key, "tenant-a")
	b := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: b("global"), Tenant: b("tenant"), User: b("user"), Identifier: b("identifier"), Credential: b("credential"), SessionFamily: b("family"), Session: b("session"), Authorization: b("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: "tenant-a", UserID: "user-a", Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: f.now.Add(-time.Minute), LastActivityAt: f.now.Add(-time.Minute), Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: "tenant-a", Subject: "user-a", Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: f.now.Add(-2 * time.Minute), ExpiresAt: f.now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewSessionService(sessionReader(func(ctx context.Context, q session.SessionLookup) (session.SessionObservation, error) {
		f.reads.Add(1)
		if q.TenantID != "tenant-a" {
			t.Fatal("unmapped tenant reached session owner")
		}
		return session.SessionObservation{Session: record, Current: authority, Active: !f.inactive, ReadStartedAt: f.now, ValidUntil: f.now.Add(20 * time.Second)}, nil
	}), session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: testClock(func() time.Time { return f.now }), MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	store, _ := memory.New(memory.Options{MaxKeys: 1024, Shards: 1})
	t.Cleanup(func() { store.Close() })
	safe, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: &safeBackend{store}, Namespace: "organization-test", Now: func() time.Time { return f.now }, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second, EmergencyMaximumKeys: 1024})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { safe.Close() })
	admin, err := organizationhttp.NewAdminRateLimiter(organizationhttp.AdminRateConfig{Shared: f.rate, Namespace: "organization-test", Key: [32]byte{1}, Now: func() time.Time { return f.now }, MaximumDuration: time.Second, Denied: func(context.Context, organizationhttp.AdminRateEvent) error { f.denials.Add(1); return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { admin.Close() })
	f.c = organizationhttp.Config{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 2048, MaximumBodyBytes: 4096, MaximumDecodedBytes: 4096, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}, Sessions: sessions, Service: f.port, SafeRate: safe, AdminRate: admin, Now: func() time.Time { return f.now }, MaximumDuration: 2 * time.Second}
	return f
}
func request(f *fixture, path, body string, keyed bool) *http.Request {
	method := http.MethodPost
	if strings.Contains(path, "/get") || strings.Contains(path, "/list") {
		method = http.MethodGet
	}
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	r.Host = "tenant.example"
	r.RemoteAddr = "198.51.100.7:54321"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+f.wire)
	if keyed {
		r.Header.Set("Idempotency-Key", "original-key")
	}
	return r
}
func handler(t testing.TB, f *fixture) http.Handler {
	t.Helper()
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, Create: true, Get: true, MemberList: true, MemberAdd: true, MemberRemove: true})
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func serve(t testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Authorization") != "" || w.Header().Get("X-CSRF-Token") != "" {
		t.Fatal("response changed credential custody or cache policy")
	}
	return w
}

func TestOrganizationUsesNeutralNativeOperationsAndExactChannels(t *testing.T) {
	f := newFixture(t)
	h := handler(t, f)
	w := serve(t, h, request(f, "/v1/organization/create", `{"name":"Native organization","slug":"native-org"}`, true))
	if w.Code != 200 || f.port.calls != 1 || f.rate.calls != 1 || f.reads.Load() != 1 || f.port.lastCreate.Validate() != nil || f.port.lastCreate.Authentication.TenantID != "tenant-a" || f.port.network != "198.51.100.7" {
		t.Fatal("create did not reach actual admitted neutral boundary", w.Code)
	}
	for _, private := range []string{f.wire, "original-key", "credential", "authority", "proof"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("private request custody escaped")
		}
	}
	if w = serve(t, h, request(f, "/v1/organization/member/add", `{"organizationID":"organization-a","userID":"target-user","role":"member","organizationVersion":3,"memberVersion":0}`, true)); w.Code != 200 || f.port.lastAdd.Validate() != nil || f.port.lastAdd.UserID != "target-user" {
		t.Fatal("member admission lost bounded versions or target", w.Code)
	}
	if w = serve(t, h, request(f, "/v1/organization/member/remove", `{"organizationID":"organization-a","userID":"target-user","organizationVersion":4,"memberVersion":1}`, false)); w.Code != 200 || f.port.lastRemove.Validate() != nil {
		t.Fatal("repeat removal lost native request", w.Code)
	}
	if w = serve(t, h, request(f, "/v1/organization/member/list?organizationID=organization-a&limit=10&cursor=after-user", "", false)); w.Code != 200 || f.port.lastRead.Cursor != "after-user" || f.port.lastRead.Limit != 10 {
		t.Fatal("bounded native cursor/page contract changed", w.Code)
	}
}

func TestOrganizationRejectsHostileInputBeforeOwners(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"cookie-only": func(r *http.Request) {
			r.Header.Del("Authorization")
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "ambient"})
		},
		"duplicate-auth": func(r *http.Request) { r.Header.Add("authorization", r.Header.Get("Authorization")) },
		"double-space": func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer  "+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		},
		"query-authority": func(r *http.Request) { r.URL.RawQuery = "tenantID=other" },
		"unknown-body": func(r *http.Request) {
			r.Body = http.NoBody
			r.ContentLength = 0
			r.Header.Set("Content-Type", "application/json")
		},
		"no-key":        func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate-key": func(r *http.Request) { r.Header.Add("idempotency-key", "other") },
		"trailer":       func(r *http.Request) { r.Trailer = http.Header{"Authorization": []string{"Bearer private"}} },
		"plaintext":     func(r *http.Request) { r.TLS = nil },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			h := handler(t, f)
			r := request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true)
			mutate(r)
			w := serve(t, h, r)
			if w.Code < 400 || f.port.calls != 0 || f.rate.calls != 0 || f.reads.Load() != 0 {
				t.Fatal("hostile envelope reached owners", w.Code)
			}
		})
	}
	for _, body := range []string{`{"name":"Name","slug":"slug","tenantID":"other"}`, `{"name":"Name","Name":"Changed","slug":"slug"}`, `{"name":"Name","slug":"slug","commandID":"client-command"}`, `{"name":"Name","slug":"slug","actorID":"admin"}`, `{"name":"Name","slug":"slug","idempotencyKey":"body-key"}`} {
		f := newFixture(t)
		w := serve(t, handler(t, f), request(f, "/v1/organization/create", body, true))
		if w.Code != 400 || f.reads.Load() != 0 || f.port.calls != 0 {
			t.Fatal("alternate identity or duplicate body reached owners", w.Code)
		}
	}
	f := newFixture(t)
	r := request(f, "/v1/organization/member/remove", `{"organizationID":"organization-a","userID":"target-user","organizationVersion":4,"memberVersion":1}`, true)
	if w := serve(t, handler(t, f), r); w.Code != 400 || f.port.calls != 0 {
		t.Fatal("repeat removal accepted a keyed variant", w.Code)
	}
}

func TestOrganizationDenialsUnknownAndAtomicRateStayDistinct(t *testing.T) {
	for _, tc := range []struct {
		err     error
		outcome identity.CommitOutcome
		status  int
		code    string
	}{
		{organization.ErrLastOwner, identity.CommitOutcomeInvalid, 409, "last_owner"},
		{organization.ErrForbidden, identity.CommitOutcomeInvalid, 403, "forbidden"},
		{organization.ErrConflict, identity.CommitOutcomeConflict, 409, "conflict"},
		{organization.ErrUnavailable, identity.CommitOutcomeUnknown, 503, "unknown"},
		{organization.ErrUnavailable, identity.CommitOutcomeNotCommitted, 503, "not_committed"},
	} {
		f := newFixture(t)
		f.port.err, f.port.outcome = tc.err, tc.outcome
		w := serve(t, handler(t, f), request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true))
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.code) {
			t.Fatal("native outcome was flattened", w.Code, w.Body.String())
		}
		if tc.outcome == identity.CommitOutcomeUnknown && !strings.Contains(w.Body.String(), "commandID") {
			t.Fatal("unknown lost original correlation")
		}
	}
	for _, mode := range []int{1, 2, 3, 4} {
		f := newFixture(t)
		f.rate.mode = mode
		want := 503
		if mode == 1 {
			want = 429
		}
		w := serve(t, handler(t, f), request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true))
		if w.Code != want || f.port.calls != 0 || f.rate.calls != 1 || f.denials.Load() != 1 {
			t.Fatal("rate denial/outage granted authority or omitted audit", w.Code)
		}
		if mode == 1 && w.Header().Get("Retry-After") != "2" {
			t.Fatal("rate retry is not bounded ceiling seconds")
		}
	}
	f := newFixture(t)
	f.inactive = true
	w := serve(t, handler(t, f), request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true))
	if w.Code != 403 || f.rate.calls != 0 || f.port.calls != 0 {
		t.Fatal("inactive session debited actor or reached native mutation", w.Code)
	}
}

func TestOrganizationFeatureOmissionAndRealWireDescription(t *testing.T) {
	f := newFixture(t)
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, Create: true, Get: true, MemberList: true, MemberAdd: true, MemberRemove: true})
	if err != nil {
		t.Fatal(err)
	}
	_, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &wire) != nil || len(wire.Paths) != 5 || wire.Paths["/v1/organization/member/remove"] == nil || f.port.calls != 0 || f.rate.calls != 0 || f.reads.Load() != 0 {
		t.Fatal("feature metadata selected placeholders or invoked owners")
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if w := serve(t, off, request(f, "/v1/organization/create", `{}`, true)); w.Code != 404 || strings.Contains(string(offDoc.JSON()), "organization") {
		t.Fatal("omission retained routes or metadata")
	}
	if _, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{}); !errors.Is(err, identityhttp.ErrInvalidInput) {
		t.Fatal("empty selection became a usable feature")
	}
}
