package reference

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/providers"
)

func discoveryConfiguration(t *testing.T) (StoreConfiguration, ReferenceDependencies) {
	t.Helper()
	config, deps, _ := serverFixture(t)
	github, err := providers.NewGitHub(providers.GitHubConfig{Version: 1, ClientID: "discovery-test-client", ClientSecret: []byte("test-only-discovery-secret"), RedirectURI: "https://app.example/github/callback"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(github.Close)
	gitlab, err := providers.NewGitLab(providers.GitLabConfig{Version: 1, ClientID: "discovery-test-client", ClientSecret: []byte("test-only-discovery-secret"), RedirectURI: "https://app.example/gitlab/callback"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gitlab.Close)
	c := StoreConfiguration{DurableAdmission: &DurableAdmissionConfiguration{}, HTTPRate: &HTTPRateConfiguration{Namespace: "discovery-auth", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: time.Second, LockTimeout: time.Second, RollbackTimeout: time.Second}, ProviderDiscovery: &ProviderDiscoveryConfiguration{Catalog: providers.CatalogConfig{Providers: []oauth.Provider{gitlab, github}, CursorKey: []byte(strings.Repeat("k", 32))}, Authorize: config.Policies.Authorize, RateNamespace: "discovery-safe", EmergencyMaximumKeys: 128, Degraded: func(context.Context, identityhttp.SafeRateEvent) error { return nil }, MaximumDuration: time.Second}}
	return c, deps
}

func TestReferenceProviderDiscoveryCopiesNativeCatalogWithoutIO(t *testing.T) {
	c, deps := discoveryConfiguration(t)
	rate, err := composeHTTPRate(c.HTTPRate, deps.PostgreSQL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rate.limiter.Close() })
	owner, err := composeProviderDiscovery(c, rate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.close)
	clear(c.ProviderDiscovery.Catalog.CursorKey)
	c.ProviderDiscovery.Catalog.Providers[0] = nil
	limit, err := providers.NewPageLimit(1)
	if err != nil {
		t.Fatal(err)
	}
	page, err := owner.catalog.ProviderList(t.Context(), providers.ProviderListRequest{Limit: limit})
	if err != nil || len(page.Page.Providers()) != 1 || page.Page.Providers()[0].ID() != "github" || page.NextCursor.String() == "" {
		t.Fatal("reference did not freeze real native catalog", err)
	}
	if !owner.rate.Configured() || owner.authorize != c.ProviderDiscovery.Authorize {
		t.Fatal("reference lost owned rate or graph policy binding")
	}
	if strings.Contains(fmt.Sprintf("%#v", c.ProviderDiscovery), "test-only-discovery-secret") {
		t.Fatal("configuration disclosed borrowed provider secrets")
	}
	if data, err := json.Marshal(c.ProviderDiscovery); err == nil || len(data) != 0 {
		t.Fatal("discovery configuration serialized")
	}
	if disabled, err := composeProviderDiscovery(StoreConfiguration{}, nil); err != nil || disabled != nil {
		t.Fatal("default selected discovery")
	}
	serverConfig, serverDeps, base := serverFixture(t)
	server, err := NewServer(serverConfig, serverDeps, base)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://health.example/v1/oauth/provider-list?limit=1", nil)
	request.RequestURI = request.URL.RequestURI()
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != 404 || strings.Contains(string(server.OpenAPI().JSON()), "/v1/oauth/provider-list") {
		t.Fatal("default reference exposed discovery route or capability", response.Code)
	}
	owner.close()
	if owner.rate.Configured() {
		t.Fatal("discovery retained live rate after owned closure")
	}
}

func TestReferenceProviderDiscoveryRejectsIncompleteOrMixedGraph(t *testing.T) {
	for name, change := range map[string]func(*StoreConfiguration){
		"http-rate":        func(c *StoreConfiguration) { c.HTTPRate = nil },
		"authorizer":       func(c *StoreConfiguration) { c.ProviderDiscovery.Authorize = nil },
		"typed-authorizer": func(c *StoreConfiguration) { c.ProviderDiscovery.Authorize = (*serverNoCallPolicy)(nil) },
		"cursor-key":       func(c *StoreConfiguration) { c.ProviderDiscovery.Catalog.CursorKey = nil },
		"duplicate-provider": func(c *StoreConfiguration) {
			c.ProviderDiscovery.Catalog.Providers[1] = c.ProviderDiscovery.Catalog.Providers[0]
		},
		"duration":          func(c *StoreConfiguration) { c.ProviderDiscovery.MaximumDuration = 31 * time.Second },
		"degradation-owner": func(c *StoreConfiguration) { c.ProviderDiscovery.Degraded = nil },
		"key-bound":         func(c *StoreConfiguration) { c.ProviderDiscovery.EmergencyMaximumKeys = 0 },
		"password":          func(c *StoreConfiguration) { c.PasswordSignin = &PasswordSigninConfiguration{} },
		"session":           func(c *StoreConfiguration) { c.Session = &SessionConfiguration{} },
		"social":            func(c *StoreConfiguration) { c.SocialOAuth = &SocialOAuthConfiguration{} },
		"preauth-http":      func(c *StoreConfiguration) { c.HTTPPreAuth = &HTTPPreAuthConfiguration{} },
	} {
		t.Run(name, func(t *testing.T) {
			c, deps := discoveryConfiguration(t)
			rate, err := composeHTTPRate(c.HTTPRate, deps.PostgreSQL)
			if err != nil {
				t.Fatal(err)
			}
			defer rate.limiter.Close()
			change(&c)
			if owner, err := composeProviderDiscovery(c, rate); err == nil || owner != nil {
				if owner != nil {
					owner.close()
				}
				t.Fatal("unsupported discovery graph admitted")
			}
		})
	}
}

func TestReferenceProviderDiscoveryLifetimeCancelsAndDrainsPublicCalls(t *testing.T) {
	_, _, f := serverFixture(t)
	f.state.durable, f.state.features.ready, f.state.features.timeout = true, true, time.Second
	s := &Server{state: f.state}
	entered, finished := make(chan struct{}), make(chan struct{})
	h := s.guardProviderDiscoveryLifetime(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Deadline(); !ok {
			t.Error("public discovery has no owned deadline")
		}
		close(entered)
		<-r.Context().Done()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	r := httptest.NewRequest(http.MethodGet, "https://health.example/v1/oauth/provider-list?limit=1", nil)
	w := httptest.NewRecorder()
	go func() { defer close(finished); h.ServeHTTP(w, r) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("public discovery required tenant authentication")
	}
	if err := (StoreSet{state: f.state}).Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("shutdown returned before public call drained")
	}
	if w.Code != 503 {
		t.Fatal("canceled public call committed success")
	}
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, r)
	if denied.Code != 503 {
		t.Fatal("closed graph admitted catalog")
	}
}

func TestReferenceProviderDiscoveryDoesNotRelaxOtherTenantGuards(t *testing.T) {
	c, deps, f := serverFixture(t)
	server, err := NewServer(c, deps, f)
	if err != nil {
		t.Fatal(err)
	}
	network, err := identityhttp.NewNetworkResolver(c.HTTP.Network)
	if err != nil {
		t.Fatal(err)
	}
	dispatched := false
	h := server.guardTenant(network, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		dispatched = true
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "https://health.example/v1/session/get", nil)
	r.RequestURI = r.URL.RequestURI()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if dispatched || w.Code < 400 {
		t.Fatal("an unrelated tenant-only operation admitted a public host", w.Code)
	}
}
