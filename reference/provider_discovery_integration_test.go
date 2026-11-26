//go:build integration

package reference_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/i18n"
	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/providers"
	"github.com/faustbrian/go-identity/reference"
)

type providerDiscoveryPolicy struct{}

func (*providerDiscoveryPolicy) Decide(context.Context, authorization.DecisionContext) (authorization.Decision, error) {
	panic("public discovery invoked subject authorization")
}

type providerDiscoveryTenant struct{}

func (providerDiscoveryTenant) ResolveTenant(context.Context) (identity.TenantID, error) {
	panic("public discovery invoked tenant resolver")
}

// Only PostgreSQL is fixture-owned. Public Reference composition owns the real
// catalog, rate backend, migration source, route and complete request lifetime.
func TestReferencePostgresProviderDiscoveryHTTPS(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	c := f.config
	selectDurableReferenceAdmission(&c)
	c.DurableAdmission.Timeout = 5 * time.Second
	c.Migrations = &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "operator", LookupKey: [32]byte{8}, LockTimeout: time.Second, CleanupTimeout: time.Second}
	c.HTTPRate = &reference.HTTPRateConfiguration{Namespace: "provider-discovery-http", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond}
	github, err := providers.NewGitHub(providers.GitHubConfig{Version: 1, ClientID: "configured-discovery-client", ClientSecret: []byte("test-only-discovery-secret"), RedirectURI: "https://app.example/github/callback"})
	if err != nil {
		t.Fatal(err)
	}
	defer github.Close()
	gitlab, err := providers.NewGitLab(providers.GitLabConfig{Version: 1, ClientID: "configured-discovery-client", ClientSecret: []byte("test-only-discovery-secret"), RedirectURI: "https://app.example/gitlab/callback"})
	if err != nil {
		t.Fatal(err)
	}
	defer gitlab.Close()
	authorize := &providerDiscoveryPolicy{}
	c.ProviderDiscovery = &reference.ProviderDiscoveryConfiguration{Catalog: providers.CatalogConfig{Providers: []oauth.Provider{gitlab, github}, CursorKey: []byte(strings.Repeat("k", 32))}, Authorize: authorize, RateNamespace: "provider-discovery-safe", EmergencyMaximumKeys: 128, Degraded: func(context.Context, identityhttp.SafeRateEvent) error {
		t.Error("healthy PostgreSQL unexpectedly selected emergency admission")
		return nil
	}, MaximumDuration: 2 * time.Second}
	deps := reference.ReferenceDependencies{PostgreSQL: f.pool}
	policies := identity.PolicySet{Authorize: authorize,
		AssessRisk: func(context.Context, identity.RiskPolicyInput) (identity.RiskPolicyDecision, error) { panic("unused") },
		MapClaims: func(context.Context, identity.ClaimsPolicyInput) (identity.ClaimsPolicyDecision, error) {
			panic("unused")
		},
		DecideRetention: func(context.Context, identity.RetentionPolicyInput) (identity.RetentionPolicyDecision, error) {
			panic("unused")
		},
		Redact: func(context.Context, identity.RedactionPolicyInput) (identity.RedactionPolicyDecision, error) {
			panic("unused")
		},
	}
	config := reference.ReferenceConfig{Profile: reference.PostgresOnly, Policies: policies, HTTP: identityhttp.TransportPolicy{Network: identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 16384, MaximumURLBytes: 2048, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 8, MaximumDepth: 4}, MaximumForwardedHops: 1, PublicHosts: []string{"127.0.0.1"}}, HandlerTimeout: 3 * time.Second, Document: identityhttp.DocumentConfig{Title: "Standalone provider discovery", Version: "1"}}, Migration: reference.MigrationPolicy{LockTimeout: time.Second, CommandRetention: time.Hour}, Workers: reference.WorkerPolicy{MaxConcurrency: 1, LeaseDuration: time.Minute, DrainTimeout: time.Second}, Tenant: reference.TenantPolicy{Resolver: providerDiscoveryTenant{}}}
	type graph struct {
		stores   reference.StoreSet
		features reference.FeatureSet
		server   *reference.Server
	}
	compose := func(selected reference.StoreConfiguration) graph {
		t.Helper()
		stores, err := reference.ComposeStores(selected, deps)
		if err != nil {
			var invalid identity.InvalidInputError
			if errors.As(err, &invalid) {
				t.Fatal("standalone discovery stores rejected field", invalid.Field)
			}
			t.Fatal("standalone discovery stores", err)
		}
		t.Cleanup(func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := stores.Close(cleanup); err != nil {
				t.Error(err)
			}
		})
		selectedProviders, err := reference.ComposeProviders(stores)
		if err != nil {
			t.Fatal(err)
		}
		workers, err := reference.ComposeWorkers(stores, selectedProviders)
		if err != nil {
			t.Fatal("discovery unexpectedly required delivery workers", err)
		}
		features, err := reference.ComposeFeatures(stores, selectedProviders, workers)
		if err != nil {
			t.Fatal(err)
		}
		server, err := reference.NewServer(config, deps, features)
		if err != nil {
			var invalid identity.InvalidInputError
			if errors.As(err, &invalid) {
				t.Fatal("standalone discovery server rejected field", invalid.Field)
			}
			t.Fatal("standalone discovery server", err)
		}
		return graph{stores, features, server}
	}
	selected := compose(c)
	modules := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "rate-limit/postgres"}
	plan := applyRequest(t, ctx, selected.stores, modules)
	for _, module := range plan.Plan.Modules {
		if module.Module != "identity/postgres" && module.Module != "identity/risk/postgres" && module.Module != "rate-limit/postgres" {
			t.Fatal("discovery selected authentication migrations")
		}
	}
	if out, err := selected.stores.ReferenceMigrationApply(ctx, plan); err != nil || out.Result.State() != reference.MigrationApplied {
		t.Fatal("existing native migrations failed", err)
	}
	if err := selected.features.Initialize(ctx); err != nil {
		t.Fatal("discovery initialization required authentication owners", err)
	}
	if _, err := selected.features.OTP(); err == nil {
		t.Fatal("discovery exposed OTP")
	}
	if _, err := selected.features.Sessions(); err == nil {
		t.Fatal("discovery exposed sessions")
	}
	if ready := selected.server.Readiness(ctx); !ready.Ready {
		t.Fatal("initialized standalone discovery not ready", ready.Failures)
	}
	for _, operation := range selected.server.OpenAPI().Operations() {
		switch operation.Record.OperationID {
		case "identity.oauth.provider-list", "identity.http.health", "identity.http.readiness":
		default:
			if operation.Route.Path != "/healthz" && operation.Route.Path != "/readyz" {
				t.Fatal("discovery advertised unrelated operation", operation.Record.OperationID)
			}
		}
	}
	api := httptest.NewUnstartedServer(selected.server.Handler())
	api.StartTLS()
	t.Cleanup(api.Close)
	client := api.Client()
	client.Timeout = 5 * time.Second
	call := func(method, path string) (int, http.Header, []byte) {
		t.Helper()
		r, err := http.NewRequestWithContext(ctx, method, api.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("public TLS discovery request failed", err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
		if err != nil || len(body) > 32768 {
			t.Fatal("unbounded discovery output", err)
		}
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" {
			t.Fatal("discovery cached or minted browser credentials")
		}
		return response.StatusCode, response.Header.Clone(), body
	}
	status, _, body := call(http.MethodGet, "/v1/oauth/provider-list?limit=1")
	var first struct {
		Page []struct {
			ID             string   `json:"id"`
			DisplayName    string   `json:"displayName"`
			SupportedModes []string `json:"supportedModes"`
		} `json:"page"`
		NextCursor string `json:"nextCursor"`
	}
	if status != 200 || json.Unmarshal(body, &first) != nil || len(first.Page) != 1 || first.Page[0].ID != "github" || first.Page[0].DisplayName != "GitHub" || len(first.Page[0].SupportedModes) != 1 || first.Page[0].SupportedModes[0] != "authorization_code" || first.NextCursor == "" {
		t.Fatal("actual public TLS catalog did not return native first page", status)
	}
	for _, hidden := range []string{"configured-discovery-client", "test-only-discovery-secret", "https://", "CursorKey", "issuer", "user:email"} {
		if strings.Contains(string(body), hidden) {
			t.Fatal("discovery leaked configuration")
		}
	}
	status, _, body = call(http.MethodGet, "/v1/oauth/provider-list?limit=1&cursor="+url.QueryEscape(first.NextCursor))
	if status != 200 || !strings.Contains(string(body), `"id":"gitlab"`) || strings.Contains(string(body), "nextCursor") {
		t.Fatal("native second page did not exhaust", status)
	}
	for _, query := range []string{"", "limit=0", "limit=101", "limit=1&userID=other", "limit=1&cursor=", "limit=2&cursor=" + url.QueryEscape(first.NextCursor)} {
		if status, _, _ := call(http.MethodGet, "/v1/oauth/provider-list?"+query); status != 400 {
			t.Fatal("invalid discovery input admitted", query, status)
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(first.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	if status, _, _ := call(http.MethodGet, "/v1/oauth/provider-list?limit=1&cursor="+base64.RawURLEncoding.EncodeToString(raw)); status != 400 {
		t.Fatal("altered native cursor admitted", status)
	}
	for _, path := range []string{"/v1/oauth/signin-start", "/v1/account/link-start", "/v1/session/get", "/v1/oauth/provider-list/"} {
		if status, _, _ := call(http.MethodGet, path); status != 404 {
			t.Fatal("unselected route executable", path, status)
		}
	}
	for _, method := range []string{http.MethodHead, http.MethodOptions} {
		status, header, body := call(method, "/v1/oauth/provider-list?limit=1")
		if status < 400 || header.Get("Access-Control-Allow-Origin") != "" || method == http.MethodHead && len(body) != 0 {
			t.Fatal("implicit HEAD, OPTIONS or CORS admitted", method, status)
		}
	}
	t.Run("localized-errors", func(t *testing.T) {
		en := []i18n.Message{
			{ID: oauthhttp.ProviderListInvalidRequestMessage, Template: "Invalid request."},
			{ID: oauthhttp.ProviderListDeniedMessage, Template: "Request denied."},
			{ID: oauthhttp.ProviderListRateLimitedMessage, Template: "Please retry later."},
			{ID: oauthhttp.ProviderListUnavailableMessage, Template: "Temporarily unavailable."},
		}
		fi := []i18n.Message{{ID: oauthhttp.ProviderListInvalidRequestMessage, Template: "Virheellinen pyyntö."}}
		localized := config
		localized.ProviderDiscoveryLocalization = &oauthhttp.ProviderListLocalizationConfig{
			DefaultLocale: "en", Catalogs: []i18n.Catalog{{Locale: "en", Version: 1, Messages: en}, {Locale: "fi", Version: 1, Messages: fi}},
		}
		localizedServer, err := reference.NewServer(localized, deps, selected.features)
		if err != nil {
			t.Fatal(err)
		}
		fi[0].Template = "caller change after construction"
		localizedAPI := httptest.NewTLSServer(localizedServer.Handler())
		defer localizedAPI.Close()
		for _, test := range []struct {
			api            *httptest.Server
			want, language string
		}{
			{api: localizedAPI, want: `{"error":"invalid_request","message":"Virheellinen pyyntö."}` + "\n", language: "fi"},
			{api: api, want: `{"error":"invalid_request"}` + "\n"},
		} {
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, test.api.URL+"/v1/oauth/provider-list?limit=0", nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("Accept-Language", "fi")
			response, err := test.api.Client().Do(r)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
			_ = response.Body.Close()
			if err != nil || response.StatusCode != 400 || response.Header.Get("Content-Language") != test.language || string(body) != test.want {
				t.Fatalf("Reference discovery localization: status %d, language %q, body %q, error %v", response.StatusCode, response.Header.Get("Content-Language"), body, err)
			}
		}
	})
	if err := selected.stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := call(http.MethodGet, "/v1/oauth/provider-list?limit=1"); status != 503 {
		t.Fatal("closed graph served catalog", status)
	}
	api.Close()
	for _, mode := range []string{"empty", "wrong-key", "budget"} {
		t.Run(mode, func(t *testing.T) {
			next := c
			copy := *c.ProviderDiscovery
			next.ProviderDiscovery = &copy
			copy.RateNamespace = "provider-discovery-" + mode
			if mode == "empty" {
				copy.Catalog.Providers = nil
			}
			if mode == "wrong-key" {
				copy.Catalog.CursorKey = []byte(strings.Repeat("z", 32))
			}
			current := compose(next)
			if err := current.features.Initialize(ctx); err != nil {
				t.Fatal(err)
			}
			api = httptest.NewUnstartedServer(current.server.Handler())
			api.StartTLS()
			defer api.Close()
			client = api.Client()
			client.Timeout = 5 * time.Second
			if mode != "budget" {
				if status, _, _ := call(http.MethodGet, "/v1/oauth/provider-list?limit=1&cursor="+url.QueryEscape(first.NextCursor)); status != 400 {
					t.Fatal("cursor transferred to different native configuration", status)
				}
				if mode == "empty" {
					status, _, body := call(http.MethodGet, "/v1/oauth/provider-list?limit=1")
					if status != 200 || string(body) != `{"page":[]}` {
						t.Fatal("empty native catalog invented provider", status)
					}
				}
				return
			}
			for i := 0; i < 120; i++ {
				status, header, _ := call(http.MethodGet, "/v1/oauth/provider-list?limit=1")
				if status == 429 {
					seconds, err := strconv.Atoi(header.Get("Retry-After"))
					if err != nil || seconds < 1 || seconds > 60 {
						t.Fatal("native safe quota lost bounded retry", header.Get("Retry-After"))
					}
					return
				}
				if status != 200 {
					t.Fatal("healthy owned quota failed", status)
				}
			}
			t.Fatal("discovery never enforced PostgreSQL shared safe quota")
		})
	}
}
