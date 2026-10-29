package apikeyhttp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
	identityhttp "github.com/faustbrian/go-identity/http"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

// These ports prove only transport mapping. Genuine current owner authority,
// persistence and no-debit reads are covered by the native/Reference consumers.
type metadataWireOwner struct {
	record apikey.Record
	get    apikey.GetRequest
	list   apikey.ListRequest
	calls  int
	err    error
	after  func()
	page   *apikey.ListResult
}

func (o *metadataWireOwner) Get(_ context.Context, r apikey.GetRequest) (apikey.GetResult, error) {
	o.get, o.calls = r, o.calls+1
	if o.after != nil {
		o.after()
	}
	return apikey.GetResult{Record: o.record}, o.err
}

func (o *metadataWireOwner) List(_ context.Context, r apikey.ListRequest) (apikey.ListResult, error) {
	o.list, o.calls = r, o.calls+1
	if o.after != nil {
		o.after()
	}
	if o.page != nil {
		return *o.page, o.err
	}
	return apikey.ListResult{Records: []apikey.Record{o.record}}, o.err
}

// Only the shared-storage seam changes consistency for an isolated wire test;
// the existing primitive still owns actual counting and limit decisions.
type metadataWireRate struct{ *memory.Store }

func (*metadataWireRate) Name() string { return "metadata-wire-admission" }
func (b *metadataWireRate) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	p := r.Policy
	r.Policy, _ = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	return b.Store.AdmitStrict(ctx, r)
}

func metadataFixture(t *testing.T) (fixture, *metadataWireOwner) {
	t.Helper()
	f := newFixture(t)
	owner, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "user-a", Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	o := &metadataWireOwner{record: apikey.Record{ID: "key-a", Owner: owner, Version: 1, AuthorityVersion: 1, ConfigurationID: "automation", ConfigurationRevision: 1, Name: "consumer metadata", Status: apikey.KeyActive, Grant: []string{"read"}, CreatedAt: f.clock.now.Add(-time.Hour), ExpiresAt: f.clock.now.Add(time.Hour), RootID: "key-a", RootVersion: 1, Issuer: "https://issuer.example", Environment: "test", Audience: "api"}}
	store, err := memory.New(memory.Options{MaxKeys: 128, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	rate, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: &metadataWireRate{store}, Namespace: "metadata-wire", Now: f.clock.Now, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second, EmergencyMaximumKeys: 128})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := rate.Close(); err != nil {
			t.Error("metadata rate cleanup", err)
		}
	})
	f.config.Create, f.config.Rotate, f.config.Revoke = false, false, false
	f.config.Creator, f.config.OrganizationCreator, f.config.Rotator, f.config.Revoker, f.config.SecretRate = nil, nil, nil, nil, nil
	f.config.Get, f.config.List = true, true
	f.config.Getter, f.config.Lister, f.config.SafeRate = o, o, rate
	return f, o
}

func metadataRequest(f fixture, path string) *http.Request {
	r := f.request("get", "")
	r.Method, r.Body, r.ContentLength = http.MethodGet, nil, 0
	r.URL.Path, r.URL.RawQuery = "/v1/apikey/get", "keyID=key-a"
	if path == "list" {
		r.URL.Path, r.URL.RawQuery = "/v1/apikey/list", "limit=1"
	}
	r.RequestURI = r.URL.RequestURI()
	r.Header.Del("Content-Type")
	r.Header.Del("Idempotency-Key")
	return r
}

func TestMetadataReadOnlySelectionReachesCurrentNativePort(t *testing.T) {
	for _, action := range []string{"get", "list"} {
		t.Run(action, func(t *testing.T) {
			f, owner := metadataFixture(t)
			feature, err := NewFeature(f.config)
			if err != nil {
				t.Fatal("read-only selection cannot compose without mutation ports", err)
			}
			h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, metadataRequest(f, action))
			var result map[string]json.RawMessage
			if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || owner.calls != 1 || f.native.calls != 0 || f.rate.calls != 0 {
				t.Fatal("safe metadata read was missing or entered mutation admission", w.Code)
			}
			if action == "get" {
				var key struct{ ID string }
				if json.Unmarshal(result["key"], &key) != nil || key.ID != "key-a" || owner.get.Validate() != nil || owner.get.Authentication.TenantID != "tenant-a" || owner.get.Authentication.Bearer.Token() != f.token || owner.get.KeyID != "key-a" {
					t.Fatal("Get did not preserve exact native bearer/tenant/position")
				}
			} else {
				var keys []struct{ ID string }
				if json.Unmarshal(result["keys"], &keys) != nil || len(keys) != 1 || keys[0].ID != "key-a" || owner.list.Validate() != nil || owner.list.Limit != 1 || owner.list.Authentication.Bearer.Token() != f.token {
					t.Fatal("List did not preserve exact bounded native page")
				}
			}
			if result["secret"] != nil || result["digest"] != nil || result["recovery"] != nil || w.Header().Get("Cache-Control") != "no-store" || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("metadata response gained credential or mutation custody")
			}
		})
	}
}

func TestMetadataQueryDeniesBeforeAuthority(t *testing.T) {
	for _, tc := range []struct{ action, query string }{
		{"get", "keyID=key-a&keyID=key-b"}, {"get", "KeyID=key-a"},
		{"get", "keyID=key-a&userID=user-b"}, {"get", "keyID=key-a&tenantID=tenant-b"},
		{"get", "keyID=key-a&organizationID=org-a"}, {"get", "keyID=key-a&cursor=position"},
		{"get", "keyID=%FF"}, {"get", "keyID="},
		{"list", "limit=0"}, {"list", "limit=201"}, {"list", "limit=01"},
		{"list", "limit=1e0"}, {"list", "limit=-1"}, {"list", "limit=1&limit=2"},
		{"list", "limit=1&actorID=other"}, {"list", "limit=1&cursor="},
		{"list", "limit=1&cursor=" + strings.Repeat("x", 513)},
		{"list", "limit=1&configurationIDs=null"},
		{"list", "limit=1&configurationIDs=" + url.QueryEscape(`["legacy","automation"]`)},
		{"list", "limit=1&configurationIDs=" + url.QueryEscape(`["automation","automation"]`)},
		{"list", "limit=1&configurationIDs=" + url.QueryEscape(`[[["automation"]]]`)},
	} {
		t.Run(tc.action+"/"+tc.query, func(t *testing.T) {
			f, owner := metadataFixture(t)
			r := metadataRequest(f, tc.action)
			r.URL.RawQuery, r.RequestURI = tc.query, ""
			w := httptest.NewRecorder()
			fixtureHandler(t, f).ServeHTTP(w, r)
			if w.Code != 400 || owner.calls != 0 || f.sessions.calls != 0 {
				t.Fatal("malformed read input acquired current authority or reached native owner", w.Code)
			}
		})
	}
}

func TestMetadataReadsRejectAlternateCredentialAndBodyChannels(t *testing.T) {
	for _, variant := range []string{"idempotency", "duplicate-bearer", "cookie-only", "body"} {
		t.Run(variant, func(t *testing.T) {
			f, owner := metadataFixture(t)
			r := metadataRequest(f, "get")
			switch variant {
			case "idempotency":
				r.Header.Set("Idempotency-Key", "not-a-read-input")
			case "duplicate-bearer":
				r.Header.Add("Authorization", "Bearer "+f.token)
			case "cookie-only":
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "session", Value: f.token})
			case "body":
				r.Body = io.NopCloser(strings.NewReader(`{}`))
				r.ContentLength = 2
				t.Cleanup(func() { _ = r.Body.Close() })
			}
			w := httptest.NewRecorder()
			fixtureHandler(t, f).ServeHTTP(w, r)
			if w.Code != 400 || owner.calls != 0 || f.sessions.calls != 0 {
				t.Fatal("read acquired credentials from an alternate channel", w.Code)
			}
		})
	}
}

func TestMetadataMapsExplicitOwnerFilterAndOpaquePosition(t *testing.T) {
	f, owner := metadataFixture(t)
	f.config.OrganizationOwned = true
	organization, err := apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerOrganization, OrganizationID: "org-a", Version: 3})
	if err != nil {
		t.Fatal(err)
	}
	owner.record.Owner, owner.record.ExpiresAt = organization, time.Time{}
	owner.record.Status, owner.record.Grant = apikey.KeyRevoked, nil
	r := metadataRequest(f, "list")
	r.URL.RawQuery = "organizationID=org-a&limit=1&cursor=opaque-position&configurationIDs=" + url.QueryEscape(`["automation"]`)
	r.RequestURI = r.URL.RequestURI()
	w := httptest.NewRecorder()
	fixtureHandler(t, f).ServeHTTP(w, r)
	var out struct {
		Keys []struct {
			Owner struct {
				Kind, OrganizationID string
				Version              uint64
			}
			ExpiresAt   *time.Time
			Status      string
			Permissions []string
		}
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Keys) != 1 || out.Keys[0].Owner.Kind != "organization" || out.Keys[0].Owner.OrganizationID != "org-a" || out.Keys[0].Owner.Version != 3 || out.Keys[0].ExpiresAt != nil || out.Keys[0].Status != "revoked" || out.Keys[0].Permissions == nil {
		t.Fatal("selected historical organization metadata changed owner/status/absent expiry", w.Code)
	}
	if owner.list.OrganizationID != "org-a" || owner.list.Cursor != "opaque-position" || !slices.Equal(owner.list.ConfigurationIDs, []string{"automation"}) || owner.list.Authentication.Bearer.Token() != f.token {
		t.Fatal("HTTP changed the native owner/filter/position custody")
	}
}

func TestMetadataRejectsWrongOwnerAndMalformedNativePages(t *testing.T) {
	for _, variant := range []string{"foreign-owner", "wrong-key", "partial-error", "too-many", "duplicate", "foreign-filter", "repeated-cursor"} {
		t.Run(variant, func(t *testing.T) {
			f, owner := metadataFixture(t)
			action := "get"
			r := metadataRequest(f, action)
			want := 503
			switch variant {
			case "foreign-owner":
				owner.record.Owner, _ = apikey.NewOwner(apikey.OwnerSpec{TenantID: "tenant-a", Kind: apikey.OwnerUser, UserID: "foreign-user", Version: 1})
			case "wrong-key":
				owner.record.ID, owner.record.RootID = "another-position", "another-position"
			case "partial-error":
				owner.err, want = apikey.ErrDenied, 403
			default:
				action = "list"
				r = metadataRequest(f, action)
				page := apikey.ListResult{Records: []apikey.Record{owner.record}}
				switch variant {
				case "too-many", "duplicate":
					page.Records = append(page.Records, owner.record)
					if variant == "duplicate" {
						r.URL.RawQuery = "limit=2"
					}
				case "foreign-filter":
					r.URL.RawQuery = "limit=1&configurationIDs=" + url.QueryEscape(`["legacy"]`)
				case "repeated-cursor":
					r.URL.RawQuery, page.NextCursor = "limit=1&cursor=same-position", "same-position"
				}
				owner.page = &page
			}
			r.RequestURI = r.URL.RequestURI()
			w := httptest.NewRecorder()
			fixtureHandler(t, f).ServeHTTP(w, r)
			var out map[string]json.RawMessage
			if w.Code != want || json.Unmarshal(w.Body.Bytes(), &out) != nil || out["key"] != nil || out["keys"] != nil || owner.calls != 1 {
				t.Fatal("invalid/failed native read disclosed a partial record/page", w.Code)
			}
		})
	}
}

func TestMetadataCurrentAuthorityAndCancellationNeverRenew(t *testing.T) {
	for _, variant := range []string{"inactive", "after-rate", "after-native", "canceled"} {
		t.Run(variant, func(t *testing.T) {
			f, owner := metadataFixture(t)
			r := metadataRequest(f, "get")
			wantCalls, wantStatus := 1, 503
			switch variant {
			case "inactive":
				f.sessions.value.Active, wantCalls, wantStatus = false, 0, 403
			case "after-rate":
				calls := 0
				f.config.Now = func() time.Time {
					calls++
					if calls > 1 {
						return f.clock.now.Add(21 * time.Second)
					}
					return f.clock.now
				}
				wantCalls = 0
			case "after-native":
				owner.after = func() { f.clock.now = f.clock.now.Add(21 * time.Second) }
			case "canceled":
				ctx, cancel := context.WithCancel(r.Context())
				defer cancel()
				r = r.WithContext(ctx)
				owner.after = cancel
			}
			w := httptest.NewRecorder()
			fixtureHandler(t, f).ServeHTTP(w, r)
			if w.Code != wantStatus || owner.calls != wantCalls || strings.Contains(w.Body.String(), "key-a") {
				t.Fatal("expired/inactive/canceled authority disclosed metadata or was renewed", w.Code, owner.calls)
			}
		})
	}
}

func TestMetadataReadRoutesShareTheExistingSafeRateBudget(t *testing.T) {
	f, owner := metadataFixture(t)
	h := fixtureHandler(t, f)
	for i := range 101 {
		action := "get"
		if i%2 == 1 {
			action = "list"
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, metadataRequest(f, action))
		if i < 100 && w.Code != 200 || i == 100 && (w.Code != 429 || w.Header().Get("Retry-After") == "") {
			t.Fatal("metadata operations split or bypassed the shared safe IP budget", i, w.Code)
		}
	}
	if owner.calls != 100 || f.native.calls != 0 || f.rate.calls != 0 {
		t.Fatal("rate denial reached metadata owner or consumed mutation admission")
	}
}

func TestMetadataFactoryRejectsMissingSelectedReadOwners(t *testing.T) {
	for _, variant := range []string{"getter", "typed-nil-getter", "lister", "safe-rate"} {
		t.Run(variant, func(t *testing.T) {
			f, owner := metadataFixture(t)
			switch variant {
			case "getter":
				f.config.Getter = nil
			case "typed-nil-getter":
				f.config.Getter = (*metadataWireOwner)(nil)
			case "lister":
				f.config.Lister = nil
			case "safe-rate":
				f.config.SafeRate = nil
			}
			if _, err := NewFeature(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) || owner.calls != 0 || f.sessions.calls != 0 {
				t.Fatal("selected incomplete read graph escaped construction or performed IO", err)
			}
		})
	}
}
