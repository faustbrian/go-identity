package scimhttp_test

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	scimhttp "github.com/faustbrian/go-identity/http/scim"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	scim "github.com/faustbrian/go-scim"
	scimpostgres "github.com/faustbrian/go-scim/postgres"
)

const managedTenant = "AAAAAAAAAAAAAAAAAAAAAQ"
const managedOrganization = "AAAAAAAAAAAAAAAAAAAAAg"
const managedConnection = "AAAAAAAAAAAAAAAAAAAAAw"
const managedActor = "AAAAAAAAAAAAAAAAAAAABA"
const managedGetPath = "/v1/scim/connection-get"
const managedListPath = "/v1/scim/connection-list"

type managedClock struct{ now time.Time }

func (c managedClock) Now() time.Time { return c.now }

type managedSessionReader struct {
	observe func(context.Context, session.SessionLookup) (session.SessionObservation, error)
}

func (s managedSessionReader) ObserveSession(ctx context.Context, q session.SessionLookup) (session.SessionObservation, error) {
	return s.observe(ctx, q)
}

type managedReadOwner struct {
	record scim.ConnectionRecord
	get    scimpostgres.ConnectionGetRequest
	list   scimpostgres.ConnectionListRequest
	calls  int
	err    error
	page   *scimpostgres.ConnectionListResult
}

func (s *managedReadOwner) ConnectionGet(ctx context.Context, r scimpostgres.ConnectionGetRequest) (scim.ConnectionRecord, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded native read")
	}
	s.calls++
	s.get = r
	return s.record, s.err
}
func (s *managedReadOwner) ConnectionList(ctx context.Context, r scimpostgres.ConnectionListRequest) (scimpostgres.ConnectionListResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded native read")
	}
	s.calls++
	s.list = r
	if s.page != nil {
		return *s.page, s.err
	}
	return scimpostgres.ConnectionListResult{Connections: []scim.ConnectionRecord{s.record}}, s.err
}

type managedRateBackend struct {
	ratelimit.StrictBackend
	requests []ratelimit.Request
	limited  bool
}

func (*managedRateBackend) Name() string { return "managed-read-test" }
func (b *managedRateBackend) AdmitStrict(_ context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	b.requests = append(b.requests, r)
	d := ratelimit.Decision{Allowed: !b.limited, Remaining: r.Policy.Limit() - 1, Limit: r.Policy.Limit(), Reset: r.Now.Add(r.Policy.Period()), Reason: ratelimit.ReasonAllowed}
	if b.limited {
		d.Remaining = 0
		d.Reason = ratelimit.ReasonLimited
		d.RetryAfter = time.Second
		return d, ratelimit.ErrRejected
	}
	return d, nil
}

type managedFixture struct {
	config                scimhttp.ManagedReadConfig
	owner                 *managedReadOwner
	backend               *managedRateBackend
	token                 string
	inactive, unavailable bool
	observations          int
}

func newManagedFixture(t *testing.T) *managedFixture {
	t.Helper()
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	f := &managedFixture{owner: &managedReadOwner{}, backend: &managedRateBackend{}}
	token, err := session.NewToken(32)
	if err != nil {
		t.Fatal(err)
	}
	f.token, _ = token.Reveal()
	key, _ := session.NewDigestKey(1, make([]byte, 32))
	digest, _ := token.Digest(key, managedTenant)
	binding := func(key string) session.AuthorityBinding { return session.AuthorityBinding{ScopeKey: key, Version: 1} }
	authority, err := session.NewAuthoritySnapshot(session.AuthoritySnapshotSpec{Global: binding("global"), Tenant: binding("tenant"), User: binding("user"), Identifier: binding("identifier"), Credential: binding("credential"), SessionFamily: binding("family"), Session: binding("session"), Authorization: binding("authorization")})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(session.BrowserSession, session.LifetimeConfig{Default: session.BrowserSession, AbsoluteTTL: time.Hour, IdleTTL: 30 * time.Minute, RefreshAfter: time.Minute, FreshFor: 15 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	record, err := session.NewSession(session.SessionSpec{SessionID: "session-a", FamilyID: "family-a", TenantID: managedTenant, UserID: managedActor, Audience: "identity-service", Version: 1, FamilyVersion: 1, Remember: remember, Authority: authority, Lookup: digest, IssuedAt: now.Add(-time.Minute), LastActivityAt: now.Add(-time.Minute), Authentication: session.AuthenticationMetadata{Kind: session.AuthenticationVerified, Proof: authentication.Proof{ID: "abcdefghijklmnopqrstuv", Tenant: managedTenant, Subject: managedActor, Method: "password", Assurance: authentication.AssuranceSingleFactor, Purpose: "session-issue", Audience: "identity-service", IssuedAt: now.Add(-2 * time.Minute), ExpiresAt: now.Add(time.Minute)}, ProofVersion: 1, CredentialID: "password-a", CredentialVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := session.NewSessionService(managedSessionReader{func(_ context.Context, q session.SessionLookup) (session.SessionObservation, error) {
		f.observations++
		if f.unavailable {
			return session.SessionObservation{}, errors.New("private session failure")
		}
		if q.TenantID != managedTenant {
			return session.SessionObservation{}, identity.ForbiddenError{}
		}
		return session.SessionObservation{Session: record, Current: authority, Active: !f.inactive, ReadStartedAt: now, ValidUntil: now.Add(20 * time.Second)}, nil
	}}, session.ServiceConfig{Profile: session.StorageStatefulOpaque, Audience: "identity-service", Clock: managedClock{now}, MaximumDuration: time.Second, ClockUncertainty: time.Millisecond, LookupKeys: []session.DigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	rate, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: f.backend, Namespace: "managed-read-test", Now: func() time.Time { return now }, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second, EmergencyMaximumKeys: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rate.Close() })
	path, _ := scim.ParseMappingPath("userName", nil, scim.DefaultLimits())
	mappings, _ := scim.NewMappingSet([]scim.Mapping{{Source: path, Target: "scim_user_name", Writable: true}})
	f.owner.record, err = scim.NewConnectionRecord(scim.ConnectionScope{TenantID: managedTenant, OrganizationID: managedOrganization, ProviderID: "managed-provider", ProviderConnectionID: managedConnection}, mappings, scim.RemoveMembership, 7)
	if err != nil {
		t.Fatal(err)
	}
	f.config = scimhttp.ManagedReadConfig{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 32768, MaximumURLBytes: 4096, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 16, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: managedTenant}}}, Sessions: sessions, Getter: f.owner, Lister: f.owner, SafeRate: rate, Now: func() time.Time { return now }, MaximumDuration: time.Second}
	return f
}
func (f *managedFixture) handler(t *testing.T) http.Handler {
	t.Helper()
	feature, err := scimhttp.NewManagedReadFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func (f *managedFixture) request(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = "tenant.example"
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "198.51.100.7:12345"
	r.Header.Set("Authorization", "Bearer "+f.token)
	return r
}
func managedServe(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestManagedReadSelectedGetAndListProjectSafeNativeResults(t *testing.T) {
	f := newManagedFixture(t)
	h := f.handler(t)
	for _, path := range []string{managedGetPath + "?connectionID=" + managedConnection, managedListPath + "?organizationID=" + managedOrganization + "&limit=1"} {
		w := managedServe(h, f.request(path))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"version":7`) || !strings.Contains(w.Body.String(), `"source":"userName"`) || strings.Contains(w.Body.String(), f.token) {
			t.Fatalf("safe native projection failed: status %d", w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("unsafe response headers")
		}
	}
	if f.owner.get.ConnectionID != managedConnection || f.owner.get.Authentication.TenantID != managedTenant || f.owner.get.Authentication.Bearer.Token() != f.token || f.owner.list.OrganizationID != managedOrganization || f.owner.list.Limit != 1 {
		t.Fatal("native request lost exact authenticated scope")
	}
	if len(f.backend.requests) != 4 {
		t.Fatal("authenticated reads must debit IP and actual-session subject")
	}
	digest := sha256.Sum256([]byte("22:" + managedTenant + managedActor))
	want, err := ratelimit.NewKey(ratelimit.KeySpec{Namespace: "managed-read-test", Version: "1", Subject: ratelimit.Subject{Kind: "subject", Value: hex.EncodeToString(digest[:])}, Hash: true})
	if err != nil || f.backend.requests[1].Key != want || f.backend.requests[3].Key != want {
		t.Fatal("safe rate subject did not come from the actual authenticated session")
	}
}

func TestManagedReadListPreservesBoundedContinuationAndEmptyPage(t *testing.T) {
	f := newManagedFixture(t)
	f.config.Getter = nil
	var bytes [55]byte
	bytes[0] = 1
	copy(bytes[1:23], managedConnection)
	cursor := base64.RawURLEncoding.EncodeToString(bytes[:])
	f.owner.page = &scimpostgres.ConnectionListResult{Connections: []scim.ConnectionRecord{f.owner.record}, NextCursor: cursor}
	h := f.handler(t)
	path := managedListPath + "?organizationID=" + managedOrganization + "&limit=1&cursor=" + cursor
	w := managedServe(h, f.request(path))
	var page scimhttp.ManagedConnectionListResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Connections) != 1 || page.NextCursor != cursor || f.owner.list.Cursor != cursor {
		t.Fatal("transport changed the native bounded continuation")
	}
	f.owner.page = &scimpostgres.ConnectionListResult{}
	w = managedServe(h, f.request(managedListPath+"?organizationID="+managedOrganization+"&limit=200"))
	if w.Code != 200 || w.Body.String() != `{"connections":[]}` {
		t.Fatalf("empty native page must be an array without a continuation: status %d", w.Code)
	}
}

func TestManagedReadRejectsNoncanonicalUnboundedAndUnselectedInputs(t *testing.T) {
	for _, path := range []string{
		managedGetPath, managedGetPath + "?connectionID=not-canonical", managedGetPath + "?connectionID=" + managedConnection + "&connectionID=" + managedConnection,
		managedGetPath + "?connectionID=" + managedConnection + "&userID=forged", managedGetPath + "?connectionID=" + managedConnection + "&organizationID=" + managedOrganization,
		managedListPath + "?organizationID=" + managedOrganization, managedListPath + "?organizationID=" + managedOrganization + "&limit=0", managedListPath + "?organizationID=" + managedOrganization + "&limit=201",
		managedListPath + "?organizationID=" + managedOrganization + "&limit=01", managedListPath + "?organizationID=" + managedOrganization + "&limit=1&cursor=", managedListPath + "?organizationID=" + managedOrganization + "&limit=1&cursor=" + strings.Repeat("x", 1025),
	} {
		t.Run(path, func(t *testing.T) {
			f := newManagedFixture(t)
			w := managedServe(f.handler(t), f.request(path))
			if w.Code != 400 || f.owner.calls != 0 || len(f.backend.requests) != 0 {
				t.Fatalf("invalid input reached native/rate: %d", w.Code)
			}
		})
	}
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") }, func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 }, func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, func(r *http.Request) { r.Trailer = http.Header{"X-Trailer": []string{"forbidden"}} }} {
		f := newManagedFixture(t)
		r := f.request(managedGetPath + "?connectionID=" + managedConnection)
		change(r)
		if w := managedServe(f.handler(t), r); w.Code != 400 || f.owner.calls != 0 {
			t.Fatalf("forbidden transport accepted: %d", w.Code)
		}
	}
}

func TestManagedReadRequiresCurrentBearerAndRateAdmission(t *testing.T) {
	for _, mode := range []string{"cookie-only", "duplicate", "inactive", "unavailable", "limited", "native-denied", "http"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedFixture(t)
			r := f.request(managedGetPath + "?connectionID=" + managedConnection)
			want := 403
			switch mode {
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: f.token})
				want = 401
			case "duplicate":
				r.Header.Add("Authorization", "Bearer "+f.token)
				want = 400
			case "inactive":
				f.inactive = true
			case "unavailable":
				f.unavailable = true
				want = 503
			case "limited":
				f.backend.limited = true
				want = 429
			case "native-denied":
				f.owner.err = identity.ForbiddenError{}
			case "http":
				r.TLS = nil
			}
			w := managedServe(f.handler(t), r)
			if w.Code != want || strings.Contains(w.Body.String(), f.token) || strings.Contains(w.Body.String(), "private") {
				t.Fatalf("%s status %d want %d", mode, w.Code, want)
			}
			if mode != "native-denied" && f.owner.calls != 0 {
				t.Fatal("denial reached native read")
			}
			if mode == "unavailable" && len(f.backend.requests) != 0 {
				t.Fatal("unavailable identity fell back to anonymous rate admission")
			}
		})
	}
}

func TestManagedReadFailsClosedForWrongScopeAndPartialNativePages(t *testing.T) {
	for _, mode := range []string{"zero", "other-connection", "other-org", "other-tenant", "oversized", "unsorted", "partial-error", "empty-continuation"} {
		t.Run(mode, func(t *testing.T) {
			f := newManagedFixture(t)
			path := managedGetPath + "?connectionID=" + managedConnection
			switch mode {
			case "zero":
				f.owner.record = scim.ConnectionRecord{}
			case "other-connection":
				path = managedGetPath + "?connectionID=AAAAAAAAAAAAAAAAAAAABQ"
			case "other-org":
				path = managedListPath + "?organizationID=AAAAAAAAAAAAAAAAAAAABQ&limit=1"
			case "other-tenant":
				scope := f.owner.record.Scope()
				scope.TenantID = "AAAAAAAAAAAAAAAAAAAABQ"
				f.owner.record, _ = scim.NewConnectionRecord(scope, f.owner.record.Mappings(), scim.RemoveMembership, 7)
			case "oversized", "unsorted":
				path = managedListPath + "?organizationID=" + managedOrganization + "&limit=1"
				if mode == "unsorted" {
					path = managedListPath + "?organizationID=" + managedOrganization + "&limit=2"
				}
				f.owner.page = &scimpostgres.ConnectionListResult{Connections: []scim.ConnectionRecord{f.owner.record, f.owner.record}}
			case "partial-error":
				path = managedListPath + "?organizationID=" + managedOrganization + "&limit=1"
				f.owner.err = identity.UnavailableError{}
			case "empty-continuation":
				path = managedListPath + "?organizationID=" + managedOrganization + "&limit=1"
				f.owner.page = &scimpostgres.ConnectionListResult{NextCursor: "opaque"}
			}
			w := managedServe(f.handler(t), f.request(path))
			if w.Code != 503 || strings.Contains(w.Body.String(), managedConnection) {
				t.Fatalf("unsafe native page was disclosed: status %d", w.Code)
			}
		})
	}
}

func FuzzManagedReadBoundedQuery(f *testing.F) {
	f.Add(managedOrganization, "1", "")
	f.Add("not-canonical", "201", "opaque")
	f.Add(managedOrganization, "01", strings.Repeat("x", 75))
	f.Fuzz(func(t *testing.T, organizationID, limit, cursor string) {
		fixture := newManagedFixture(t)
		query := url.Values{"organizationID": []string{organizationID}, "limit": []string{limit}}
		if cursor != "" {
			query.Set("cursor", cursor)
		}
		response := managedServe(fixture.handler(t), fixture.request(managedListPath+"?"+query.Encode()))
		if response.Code != 200 && response.Code != 400 && response.Code != 503 || strings.Contains(response.Body.String(), fixture.token) {
			t.Fatalf("query escaped the bounded safe response: %d", response.Code)
		}
	})
}

func TestManagedReadFeatureSelectionAndBulkCoexist(t *testing.T) {
	f := newManagedFixture(t)
	if _, err := scimhttp.NewManagedReadFeature(scimhttp.ManagedReadConfig{}); err == nil {
		t.Fatal("empty selection must fail")
	}
	f.config.Lister = nil
	h := f.handler(t)
	if w := managedServe(h, f.request(managedListPath+"?organizationID="+managedOrganization+"&limit=1")); w.Code != 404 {
		t.Fatalf("unselected List route: %d", w.Code)
	}
	feature, err := scimhttp.NewManagedReadFeature(f.config)
	if err != nil {
		t.Fatal(err)
	}
	bulk := newProtocolFixture()
	bulkFeature, err := scimhttp.NewBulkFeature(bulk.config)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: append(bulkFeature.Operations(), feature.Operations()...)})
	if err != nil {
		t.Fatal("combine under the canonical SCIM owner", err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{combined}})
	if err != nil || len(ops) != 3 {
		t.Fatal("managed selection must coexist with Bulk", err)
	}
	_, document := protocolRouter(t, f.config.Network, ops)
	if strings.Contains(string(document.JSON()), f.token) {
		t.Fatal("document disclosed bearer")
	}
}
