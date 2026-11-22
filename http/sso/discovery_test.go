package ssohttp

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/session"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
	"github.com/faustbrian/go-rate-limit/v2/memory"
	"github.com/faustbrian/go-sso"
)

const testTenant identity.TenantID = "tenant-one"

type discoveryProbe struct {
	t           testing.TB
	calls       int
	beforeReply func()
}

func (p *discoveryProbe) ForTenantBrowser(tenant identity.TenantID, ip netip.Addr, device string) (*sso.Service, error) {
	if tenant != testTenant || ip != netip.MustParseAddr("192.0.2.17") || device == "" {
		p.t.Fatal("discovery did not receive the trusted host/IP/device binding")
	}
	return sso.NewDiscoveryService(time.Second, p)
}

func (p *discoveryProbe) DiscoverProvider(ctx context.Context, domain string) (sso.DiscoverResult, error) {
	if _, bounded := ctx.Deadline(); !bounded {
		p.t.Fatal("unbounded discovery")
	}
	p.calls++
	if p.beforeReply != nil {
		p.beforeReply()
	}
	if domain == "example.test" {
		return sso.DiscoverResult{Matched: true, ProviderID: "approved-oidc", Protocol: "oidc", RequiresConfirmation: true}, nil
	}
	return sso.DiscoverResult{}, nil
}

type testSharedRate struct{ *memory.Store }

func (testSharedRate) Name() string { return "discovery-test-shared" }
func (b testSharedRate) AdmitStrict(ctx context.Context, r ratelimit.Request) (ratelimit.Decision, error) {
	p := r.Policy
	var err error
	r.Policy, err = ratelimit.NewPolicy(ratelimit.PolicySpec{ID: p.ID(), Revision: p.Revision(), Algorithm: p.Algorithm(), Capacity: p.Capacity(), Period: p.Period(), Consistency: ratelimit.ConsistencyProcessLocal})
	if err != nil {
		return ratelimit.Decision{}, err
	}
	return b.Store.AdmitStrict(ctx, r)
}

func discoveryFixture(t testing.TB) (Config, *discoveryProbe, *http.Cookie) {
	t.Helper()
	now := func() time.Time { return time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC) }
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-identity_device", SameSite: http.SameSiteStrictMode})
	if err != nil {
		t.Fatal(err)
	}
	key, err := session.NewBrowserDeviceKey(1, []byte("synthetic-discovery-browser-device"))
	if err != nil {
		t.Fatal(err)
	}
	device := session.BrowserDeviceConfig{Cookie: cookie, Namespace: "sso-discovery", Lifetime: time.Hour, ActiveVersion: 1, Keys: []session.BrowserDeviceKey{key}}
	codec, err := session.NewBrowserDeviceCodec(device)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := codec.Issue(context.Background(), now(), testTenant, "https://tenant.example")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := http.ParseSetCookie(issued.CookieHeader())
	if err != nil {
		t.Fatal(err)
	}
	storage, err := memory.New(memory.Options{MaxKeys: 128, Shards: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { storage.Close() })
	limiter, err := identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: testSharedRate{storage}, Namespace: "sso-discovery-test", IdentifierKey: [32]byte{1}, Now: now, MaximumDuration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { limiter.Close() })
	probe := &discoveryProbe{t: t}
	network := identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 8192, MaximumURLBytes: 2048, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 4, MaximumDepth: 4}, MaximumForwardedHops: 4, TenantHosts: []identityhttp.TenantHost{{Host: "tenant.example", TenantID: testTenant}, {Host: "other.example", TenantID: "tenant-two"}}, PublicHosts: []string{"public.example"}}
	return Config{Network: network, BrowserDevice: device, Discovery: probe, Rate: limiter, Now: now, MaximumDuration: time.Second}, probe, credential
}

func discoveryRouter(t testing.TB, config Config, selected bool) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	services := identityhttp.FeatureServices{}
	if selected {
		feature, err := NewFeature(config)
		if err != nil {
			t.Fatal(err)
		}
		services.Features = []identityhttp.Feature{feature}
	}
	ops, err := identityhttp.NewOperationDescriptors(services)
	if err != nil {
		t.Fatal(err)
	}
	returnHandler, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: config.Network, HandlerTimeout: time.Second, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	return returnHandler, doc
}

func discoveryRequest(query string, cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/v1/sso/discover", nil)
	r.URL.RawQuery = query
	r.RequestURI = r.URL.RequestURI()
	r.Host, r.TLS = "tenant.example", &tls.ConnectionState{}
	r.RemoteAddr = "192.0.2.17:32000"
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func TestDiscoverySelectedRouteProjectsOnlySafeChoice(t *testing.T) {
	config, owner, device := discoveryFixture(t)
	off, absent := discoveryRouter(t, config, false)
	w := httptest.NewRecorder()
	off.ServeHTTP(w, discoveryRequest("emailOrDomain=example.test", device))
	if w.Code != http.StatusNotFound || strings.Contains(string(absent.JSON()), "/v1/sso/discover") || owner.calls != 0 {
		t.Fatal("unselected discovery exposed a route, metadata or owner call", w.Code)
	}
	on, selected := discoveryRouter(t, config, true)
	if document := string(selected.JSON()); !strings.Contains(document, `"/v1/sso/discover"`) || !strings.Contains(document, `"operationId":"identity.sso.discover"`) || !strings.Contains(document, `"name":"emailOrDomain"`) {
		t.Fatal("OpenAPI did not publish the selected wire contract")
	}
	for _, sample := range []struct{ query, want string }{
		{"emailOrDomain=unknown%2Balias%40EXAMPLE.test", `{"matched":true,"providerID":"approved-oidc","protocol":"oidc","requiresConfirmation":true}`},
		{"emailOrDomain=unverified.test", `{"matched":false,"requiresConfirmation":false}`},
	} {
		w := httptest.NewRecorder()
		on.ServeHTTP(w, discoveryRequest(sample.query, device))
		if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != sample.want || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("unexpected discovery projection, status or cache policy", w.Code)
		}
	}
	if owner.calls != 2 {
		t.Fatal("selected queries did not reach the exact discovery owner")
	}
}

func TestDiscoveryRejectsAmbiguousInputAndForeignBrowser(t *testing.T) {
	config, owner, device := discoveryFixture(t)
	h, _ := discoveryRouter(t, config, true)
	for _, query := range []string{"", "emailOrDomain=", "emailordomain=example.test", "emailOrDomain=example.test&emailOrDomain=foreign.test", "emailOrDomain=example.test&tenantID=other", "emailOrDomain=%ZZ", "emailOrDomain=" + strings.Repeat("a", 321)} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, discoveryRequest(query, device))
		if w.Code != http.StatusBadRequest {
			t.Fatal("closed query accepted or misclassified", w.Code)
		}
	}
	for name, mutate := range map[string]func(*http.Request){
		"idempotency":      func(r *http.Request) { r.Header.Set("Idempotency-Key", "forbidden") },
		"authorization":    func(r *http.Request) { r.Header.Set("Authorization", "Bearer ignored") },
		"no device":        func(r *http.Request) { r.Header.Del("Cookie") },
		"broken device":    func(r *http.Request) { r.Header.Set("Cookie", "__Host-identity_device=broken") },
		"duplicate device": func(r *http.Request) { r.AddCookie(device) },
		"wrong host":       func(r *http.Request) { r.Host = "other.example" },
		"public realm":     func(r *http.Request) { r.Host = "public.example" },
		"cross-origin":     func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") },
		"forwarding spoof": func(r *http.Request) { r.Header.Set("Forwarded", "for=192.0.2.8;host=other.example;proto=https") },
	} {
		t.Run(name, func(t *testing.T) {
			r := discoveryRequest("emailOrDomain=example.test", device)
			mutate(r)
			w := httptest.NewRecorder()
			before := owner.calls
			h.ServeHTTP(w, r)
			if w.Code < 400 || strings.Contains(w.Body.String(), "approved-oidc") || owner.calls != before {
				t.Fatal("alternate authority channel reached discovery", w.Code)
			}
		})
	}
}

func TestDiscoveryAcceptsOnlyTheConfiguredProxyChain(t *testing.T) {
	config, owner, device := discoveryFixture(t)
	config.Network.TrustedProxyCIDRs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	h, _ := discoveryRouter(t, config, true)
	r := discoveryRequest("emailOrDomain=example.test", device)
	r.RemoteAddr, r.Host, r.TLS = "10.0.0.4:32000", "edge.example", nil
	r.Header.Set("Forwarded", "for=192.0.2.17;host=tenant.example;proto=https")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || owner.calls != 1 {
		t.Fatal("verified proxy chain did not preserve external tenant and client", w.Code)
	}
}

func TestDiscoveryRateDenialHasRetryAndNeverTouchesNativeLookup(t *testing.T) {
	config, owner, device := discoveryFixture(t)
	h, _ := discoveryRouter(t, config, true)
	for i := range 21 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, discoveryRequest("emailOrDomain=example.test", device))
		if i < 20 && w.Code != http.StatusOK || i == 20 && (w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "30" || strings.Contains(w.Body.String(), "approved-oidc")) {
			t.Fatal("incorrect shared-IP denial or retry", i, w.Code)
		}
	}
	if owner.calls != 20 {
		t.Fatal("throttled request reached native discovery")
	}
}

func TestDiscoveryWithholdsResultIfOriginalBrowserDeviceExpires(t *testing.T) {
	config, owner, device := discoveryFixture(t)
	now := config.Now()
	config.Now = func() time.Time { return now }
	owner.beforeReply = func() { now = now.Add(time.Hour) }
	h, _ := discoveryRouter(t, config, true)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, discoveryRequest("emailOrDomain=example.test", device))
	if owner.calls != 1 || w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "approved-oidc") {
		t.Fatal("an expired device received a provider choice", w.Code)
	}
}

func FuzzDiscoveryQueryDoesNotInventAuthority(f *testing.F) {
	for _, seed := range []string{"emailOrDomain=example.test", "emailOrDomain=%40.example", "emailOrDomain=a&emailOrDomain=b", "tenant=chosen", "emailOrDomain=%FF"} {
		f.Add(seed)
	}
	decoder, err := identityhttp.NewRequestDecoder(identityhttp.Limits{MaximumHeaderBytes: 8192, MaximumURLBytes: 2048, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 4, MaximumDepth: 4})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, query string) {
		if len(query) > 4096 {
			return
		}
		got, err := decodeDiscoveryQuery(decoder, discoveryRequest(query, nil))
		if err != nil {
			if got != (sso.DiscoverRequest{}) {
				t.Fatal("bad query retained discovery input")
			}
			return
		}
		want, err := url.ParseQuery(query)
		if err != nil || len(want) != 1 || len(want["emailOrDomain"]) != 1 || got.EmailOrDomain != want.Get("emailOrDomain") || len(got.EmailOrDomain) == 0 || len(got.EmailOrDomain) > 320 {
			t.Fatal("decoder invented or normalized an unbounded lookup")
		}
	})
}
