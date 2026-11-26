package oauthhttp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/providers"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
)

type providerListBackend struct {
	localStrict
	err    error
	debits int
}

func (b *providerListBackend) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	b.debits++
	if b.err != nil {
		return ratelimit.Decision{}, b.err
	}
	return b.localStrict.AdmitStrict(ctx, r)
}

type providerListFixture struct {
	config   oauthhttp.ProviderListConfig
	backend  *providerListBackend
	degraded []identityhttp.SafeRateEvent
}

func newProviderListFixture(t testing.TB) *providerListFixture {
	t.Helper()
	github, err := providers.NewGitHub(providers.GitHubConfig{Version: 1, ClientID: "private-catalog-client", ClientSecret: []byte("test-only-private-catalog-secret"), RedirectURI: "https://app.example/github/callback"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(github.Close)
	gitlab, err := providers.NewGitLab(providers.GitLabConfig{Version: 1, ClientID: "private-catalog-client", ClientSecret: []byte("test-only-private-catalog-secret"), RedirectURI: "https://app.example/gitlab/callback"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gitlab.Close)
	catalog, err := providers.NewCatalog(providers.CatalogConfig{Providers: []oauth.Provider{gitlab, github}, CursorKey: []byte(strings.Repeat("k", 32))})
	if err != nil {
		t.Fatal(err)
	}
	store, err := memory.New(memory.Options{MaxKeys: 256, Shards: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	f := &providerListFixture{backend: &providerListBackend{localStrict: localStrict{store}}}
	rate, err := identityhttp.NewSafeRateLimiter(identityhttp.SafeRateConfig{Shared: f.backend, Namespace: "provider-list", Now: func() time.Time { return time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC) }, MaximumDuration: time.Second, EmergencyMaximumKeys: 256, Degraded: func(_ context.Context, e identityhttp.SafeRateEvent) error {
		f.degraded = append(f.degraded, e)
		return nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rate.Close() })
	f.config = oauthhttp.ProviderListConfig{Catalog: catalog, Rate: rate, MaximumDuration: time.Second, Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 16384, MaximumURLBytes: 2048, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 8, MaximumDepth: 4}, MaximumForwardedHops: 1, PublicHosts: []string{"app.example"}, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: "tenant-a"}}}}
	return f
}

func providerListRequest(query string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://app.example/v1/oauth/provider-list?"+query, nil)
	r.RequestURI = r.URL.RequestURI()
	r.RemoteAddr = "192.0.2.8:1234"
	return r
}

func providerListDocumented(t testing.TB, c oauthhttp.ProviderListConfig) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	feature, err := oauthhttp.NewProviderListFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Public configured providers", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h, doc
}

func serveProviderList(t testing.TB, h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("Location") != "" {
		t.Fatal("catalog response cached or minted browser authority")
	}
	return w
}

func TestProviderListPublicDocumentedPagesUseRealCatalog(t *testing.T) {
	f := newProviderListFixture(t)
	h, doc := providerListDocumented(t, f.config)
	r := providerListRequest("limit=1")
	r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "ambient-cookie-is-not-authority"})
	w := serveProviderList(t, h, r)
	var first struct {
		Page       []map[string]json.RawMessage `json:"page"`
		NextCursor string                       `json:"nextCursor"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &first) != nil || len(first.Page) != 1 || string(first.Page[0]["id"]) != `"github"` || string(first.Page[0]["displayName"]) != `"GitHub"` || string(first.Page[0]["supportedModes"]) != `["authorization_code"]` || len(first.Page[0]) != 3 || first.NextCursor == "" {
		t.Fatal("public catalog lost native bounded projection", w.Code, w.Body.String())
	}
	last := serveProviderList(t, h, providerListRequest("limit=1&cursor="+url.QueryEscape(first.NextCursor)))
	var page map[string]json.RawMessage
	if last.Code != 200 || json.Unmarshal(last.Body.Bytes(), &page) != nil || len(page) != 1 || !strings.Contains(string(page["page"]), `"gitlab"`) {
		t.Fatal("continuation did not exhaust configured page", last.Code)
	}
	for _, hidden := range []string{"private-catalog", "test-only", "ClientID", "clientID", "issuer", "https://", "CursorKey", "secret", "openid", "user:email"} {
		if strings.Contains(w.Body.String()+last.Body.String(), hidden) {
			t.Fatal("catalog disclosed confidential provider configuration")
		}
	}
	var wire struct {
		Paths map[string]map[string]struct {
			Security   []any `json:"security"`
			Parameters []struct {
				Name     string
				Required bool
				Schema   map[string]json.RawMessage
			}
			Responses map[string]json.RawMessage
		} `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &wire) != nil || len(wire.Paths) != 1 {
		t.Fatal("catalog advertised unrelated OAuth operations")
	}
	get := wire.Paths["/v1/oauth/provider-list"]["get"]
	if len(get.Security) != 0 || len(get.Parameters) != 2 || get.Responses["200"] == nil {
		t.Fatal("public catalog document introduced credentials or omitted wire contract")
	}
	for _, p := range get.Parameters {
		if p.Name == "limit" && (!p.Required || string(p.Schema["minimum"]) != "1" || string(p.Schema["maximum"]) != "100" || p.Schema["default"] != nil) {
			t.Fatal("wire limit diverges from actual native bound")
		}
		if p.Name == "cursor" && p.Required {
			t.Fatal("first page requires a fabricated cursor")
		}
	}
	if f.backend.debits != 2 {
		t.Fatal("public reads did not use one shared IP debit each")
	}
	for _, host := range []string{"app.example", "tenant.example"} {
		r := providerListRequest("limit=100")
		r.Host = host
		if w := serveProviderList(t, h, r); w.Code != 200 {
			t.Fatal("allowlisted public discovery host rejected", host, w.Code)
		}
	}
	empty, err := providers.NewCatalog(providers.CatalogConfig{CursorKey: []byte(strings.Repeat("e", 32))})
	if err != nil {
		t.Fatal(err)
	}
	f.config.Catalog = empty
	h, _ = providerListDocumented(t, f.config)
	if w := serveProviderList(t, h, providerListRequest("limit=100")); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"page":[]}` {
		t.Fatal("empty catalog invented providers or null page", w.Code)
	}
}

func TestProviderListRejectsInvalidInputBeforeRateAndExactDispatch(t *testing.T) {
	f := newProviderListFixture(t)
	h, _ := providerListDocumented(t, f.config)
	for _, query := range []string{"", "limit=0", "limit=101", "limit=01", "limit=-1", "limit=%2B1", "limit=1&limit=2", "limit=1&Limit=2", "limit=1&cursor=", "limit=1&cursor=!", "limit=1&cursor=" + strings.Repeat("a", 513), "limit=1&cursor=one&cursor=two", "limit=1&provider=github", "limit=1&userID=other", "limit=1&tenantID=other", "limit=1&idempotencyKey=other", "limit=1&cursor=%FF", "limit=1&cursor=%"} {
		if w := serveProviderList(t, h, providerListRequest(query)); w.Code != 400 {
			t.Fatal("invalid query admitted", query, w.Code)
		}
	}
	for name, change := range map[string]func(*http.Request){
		"authorization": func(r *http.Request) { r.Header.Set("Authorization", "Bearer irrelevant") },
		"retry-key":     func(r *http.Request) { r.Header.Set("Idempotency-Key", "irrelevant") },
		"body":          func(r *http.Request) { r.Body = http.NoBody; r.ContentLength = 1 },
		"unframed-body": func(r *http.Request) { r.Body = http.MaxBytesReader(nil, http.NoBody, 1) },
		"trailer":       func(r *http.Request) { r.Trailer = http.Header{"X-Test": {"x"}} },
		"http":          func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" },
		"host":          func(r *http.Request) { r.Host = "foreign.example" },
	} {
		t.Run(name, func(t *testing.T) {
			r := providerListRequest("limit=1")
			change(r)
			if w := serveProviderList(t, h, r); w.Code < 400 {
				t.Fatal("alternate catalog channel admitted", w.Code)
			}
		})
	}
	if f.backend.debits != 0 {
		t.Fatal("invalid catalog requests consumed safe rate")
	}
	for _, path := range []string{"/v1/oauth/provider-list/", "/v1/oauth/Provider-list", "/v1/oauth/%70rovider-list"} {
		r := httptest.NewRequest(http.MethodGet, "https://app.example"+path+"?limit=1", nil)
		if w := serveProviderList(t, h, r); w.Code != 404 {
			t.Fatal("route alias admitted", path, w.Code)
		}
	}
	r := providerListRequest("limit=1")
	r.Method = http.MethodHead
	if w := serveProviderList(t, h, r); w.Code != 405 || w.Header().Get("Allow") != "GET" || w.Body.Len() != 0 {
		t.Fatal("implicit HEAD enabled")
	}
	off, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Disabled catalog", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc.JSON()), "/v1/oauth/provider-list") || serveProviderList(t, off, providerListRequest("limit=1")).Code != 404 {
		t.Fatal("unselected catalog exposed route or metadata")
	}
}

func TestProviderListNativeCursorAuthenticationAndSafeRateOwner(t *testing.T) {
	f := newProviderListFixture(t)
	h, _ := providerListDocumented(t, f.config)
	forged := base64.RawURLEncoding.EncodeToString(make([]byte, 37))
	if w := serveProviderList(t, h, providerListRequest("limit=1&cursor="+forged)); w.Code != 400 || strings.Contains(w.Body.String(), forged) {
		t.Fatal("unauthenticated opaque cursor selected native page", w.Code)
	}
	for i := 1; i < 100; i++ {
		if w := serveProviderList(t, h, providerListRequest("limit=1")); w.Code != 200 {
			t.Fatal("safe native budget denied early", i, w.Code)
		}
	}
	if w := serveProviderList(t, h, providerListRequest("limit=1")); w.Code != 429 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("catalog did not retain native safe IP100/minute budget", w.Code, w.Header().Get("Retry-After"))
	}
	f = newProviderListFixture(t)
	f.backend.err = ratelimit.ErrUnavailable
	h, _ = providerListDocumented(t, f.config)
	for i := 0; i < 20; i++ {
		if w := serveProviderList(t, h, providerListRequest("limit=1")); w.Code != 200 {
			t.Fatal("native emergency policy not preserved", i, w.Code)
		}
	}
	if w := serveProviderList(t, h, providerListRequest("limit=1")); w.Code != 429 || len(f.degraded) != 21 || f.degraded[20].Allowed || f.degraded[20].OperationID != "identity.oauth.provider-list" {
		t.Fatal("native safe fallback invented a provider-specific policy", w.Code)
	}
	f.backend.err = errors.New("private ambiguous rate diagnostic")
	if w := serveProviderList(t, h, providerListRequest("limit=1")); w.Code != 503 || w.Header().Get("Retry-After") != "" || strings.Contains(w.Body.String(), "private") {
		t.Fatal("ambiguous rate failure exposed page or diagnostics", w.Code)
	}
}

type providerListFailure struct {
	before func()
	err    error
}

func (p *providerListFailure) ProviderList(ctx context.Context, _ providers.ProviderListRequest) (providers.ProviderListResult, error) {
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded provider catalog call")
	}
	if p.before != nil {
		p.before()
	}
	return providers.ProviderListResult{}, p.err
}

func TestProviderListRequiresOwnersAndWithholdsFailedOrLateOutput(t *testing.T) {
	for _, change := range []func(*oauthhttp.ProviderListConfig){func(c *oauthhttp.ProviderListConfig) { c.Catalog = nil }, func(c *oauthhttp.ProviderListConfig) { c.Catalog = (*providerListFailure)(nil) }, func(c *oauthhttp.ProviderListConfig) { c.Rate = nil }, func(c *oauthhttp.ProviderListConfig) { c.MaximumDuration = 31 * time.Second }} {
		f := newProviderListFixture(t)
		change(&f.config)
		if _, err := oauthhttp.NewProviderListFeature(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("incomplete catalog composition accepted", err)
		}
	}
	for _, mode := range []string{"invalid", "denied", "unavailable", "unknown", "cancelled", "panic", "closed-rate"} {
		t.Run(mode, func(t *testing.T) {
			f := newProviderListFixture(t)
			p := &providerListFailure{}
			f.config.Catalog = p
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := 503
			switch mode {
			case "invalid":
				p.err = providers.ProviderListInvalidRequestError{}
				want = 400
			case "denied":
				p.err = providers.ProviderListAuthorizationDeniedError{}
				want = 403
			case "unavailable":
				p.err = providers.ProviderListUnavailableError{RetryAfter: time.Hour}
			case "unknown":
				p.err = errors.New("private catalog failure")
			case "cancelled":
				p.before = cancel
			case "panic":
				p.before = func() { panic("private catalog failure") }
			case "closed-rate":
				if err := f.config.Rate.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "closed-rate" {
				if _, err := oauthhttp.NewProviderListHandler(f.config); !errors.Is(err, identityhttp.ErrInvalidInput) {
					t.Fatal("closed rate owner accepted")
				}
				return
			}
			h, _ := providerListDocumented(t, f.config)
			w := serveProviderList(t, h, providerListRequest("limit=1").WithContext(ctx))
			var out map[string]string
			if w.Code != want || json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out) != 1 || out["error"] == "" || strings.Contains(w.Body.String(), "private") || w.Header().Get("Retry-After") != "" {
				t.Fatal("failed or late catalog disclosed output", mode, w.Code)
			}
		})
	}
}

func FuzzProviderListClosedQuery(f *testing.F) {
	for _, seed := range []string{"limit=1", "limit=100", "", "limit=01", "limit=1&cursor=!", "limit=1&cursor=", "limit=1&limit=2", "limit=1&tenantID=other", "limit=1&cursor=%FF"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 2048 {
			return
		}
		x := newProviderListFixture(t)
		h, err := oauthhttp.NewProviderListHandler(x.config)
		if err != nil {
			t.Fatal(err)
		}
		r := providerListRequest("limit=1")
		r.URL.RawQuery = raw
		r.RequestURI = r.URL.RequestURI()
		w := serveProviderList(t, h, r)
		if w.Code == 200 {
			var out struct{ Page []map[string]any }
			if json.Unmarshal(w.Body.Bytes(), &out) != nil || len(out.Page) > 2 {
				t.Fatal("hostile query escaped bounded safe result")
			}
		}
		if strings.Contains(w.Body.String(), "private-catalog") {
			t.Fatal("hostile query leaked configuration")
		}
	})
}
