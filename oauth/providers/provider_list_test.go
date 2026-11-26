package providers_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/providers"
)

func providerListOwners(t *testing.T) []oauth.Provider {
	t.Helper()
	kc := keycloakConfig(t)
	k, err := providers.NewKeycloak(kc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	g, err := providers.NewGoogle(providers.GoogleConfig{Version: 7, ClientID: "public-list-client", ClientSecret: []byte("private-list-secret"), RedirectURI: "https://application.example/google/callback", KeySet: kc.KeySet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(g.Close)
	gh, err := providers.NewGitHub(githubConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gh.Close)
	gl, err := providers.NewGitLab(providers.GitLabConfig{Version: 1, ClientID: "private-gitlab-client", ClientSecret: []byte("private-gitlab-secret"), RedirectURI: "https://application.example/gitlab/callback"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gl.Close)
	return []oauth.Provider{k, g, gl, gh}
}

func providerListConfig(owners ...oauth.Provider) providers.CatalogConfig {
	return providers.CatalogConfig{Providers: owners, CursorKey: []byte(strings.Repeat("k", 32))}
}

func providerListLimit(t *testing.T, value int) providers.PageLimit {
	t.Helper()
	limit, err := providers.NewPageLimit(value)
	if err != nil {
		t.Fatal(err)
	}
	return limit
}

func TestProviderListPublicConsumerSelectedFactsAndStablePages(t *testing.T) {
	owners := providerListOwners(t)
	c, err := providers.NewCatalog(providerListConfig(owners...))
	if err != nil {
		t.Fatal(err)
	}
	var operation providers.Catalog = c
	request := providers.ProviderListRequest{Limit: providerListLimit(t, 2)}
	first, err := operation.ProviderList(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	items := first.Page.Providers()
	if len(items) != 2 || items[0].ID() != "github" || items[0].DisplayName() != "GitHub" || items[1].ID() != "gitlab" || first.NextCursor.String() == "" {
		t.Fatal("configured providers were not sorted into a bounded first page")
	}
	for _, item := range items {
		if !slices.Equal(item.SupportedModes(), []providers.ProviderMode{providers.AuthorizationCodeMode}) {
			t.Fatal("advertised an unselected native-token, signup or refresh mode")
		}
	}
	repeated, err := operation.ProviderList(context.Background(), request)
	if err != nil || !reflect.DeepEqual(first, repeated) {
		t.Fatal("same request did not return the same immutable page and cursor")
	}
	cursor, err := providers.ParseCursor(first.NextCursor.String())
	if err != nil {
		t.Fatal(err)
	}
	last, err := operation.ProviderList(context.Background(), providers.ProviderListRequest{Cursor: cursor, Limit: request.Limit})
	if err != nil {
		t.Fatal(err)
	}
	items = last.Page.Providers()
	if len(items) != 2 || items[0].ID() != "google" || items[0].DisplayName() != "Google" || items[1].ID() != "keycloak" || items[1].DisplayName() != "Keycloak" || last.NextCursor.String() != "" {
		t.Fatal("last page did not exhaust exactly the selected providers")
	}
	// Deployment instances share configured cursor keys, never in-memory state.
	slices.Reverse(owners)
	other, err := providers.NewCatalog(providerListConfig(owners...))
	if err != nil {
		t.Fatal(err)
	}
	continued, err := other.ProviderList(context.Background(), providers.ProviderListRequest{Cursor: cursor, Limit: request.Limit})
	if err != nil || !reflect.DeepEqual(last, continued) {
		t.Fatal("equivalent snapshot on another instance could not continue the page")
	}
}

func TestProviderListSafeProjectionCannotMutateCatalog(t *testing.T) {
	owners := providerListOwners(t)
	config := providerListConfig(owners...)
	c, err := providers.NewCatalog(config)
	if err != nil {
		t.Fatal(err)
	}
	clear(config.CursorKey)
	config.Providers[0] = nil
	request := providers.ProviderListRequest{Limit: providerListLimit(t, 100)}
	result, err := c.ProviderList(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	original := result.Page.Providers()
	modified := result.Page.Providers()
	modified[0] = providers.SafeProvider{}
	modes := original[0].SupportedModes()
	modes[0] = "id_token"
	again, err := c.ProviderList(context.Background(), request)
	if err != nil || len(again.Page.Providers()) != 4 || again.Page.Providers()[0].ID() != "github" || again.Page.Providers()[0].SupportedModes()[0] != providers.AuthorizationCodeMode {
		t.Fatal("caller mutated configured provider facts or safe page storage")
	}
	wire, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var object struct {
		Page       []map[string]json.RawMessage
		NextCursor string
	}
	if json.Unmarshal(wire, &object) != nil || len(object.Page) != 4 {
		t.Fatal("safe projection was not usable as a direct consumer result")
	}
	for _, item := range object.Page {
		if len(item) != 3 || item["ID"] == nil || item["DisplayName"] == nil || item["SupportedModes"] == nil {
			t.Fatal("result contained facts beyond ID, display name and selected modes")
		}
	}
	for _, forbidden := range []string{"private-", "https://", "registered-client", "openid", "user:email", "CursorKey", "TokenEndpoint"} {
		if strings.Contains(string(wire), forbidden) || strings.Contains(fmt.Sprintf("%#v", result), forbidden) {
			t.Fatal("public result disclosed configuration instead of safe facts")
		}
	}
}

func TestProviderListCursorTamperScopeAndRequestBounds(t *testing.T) {
	owners := providerListOwners(t)
	otherGoogle, err := providers.NewGoogle(providers.GoogleConfig{Version: 8, ClientID: "public-list-client", ClientSecret: []byte("private-list-secret"), RedirectURI: "https://application.example/google/callback", KeySet: keycloakConfig(t).KeySet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(otherGoogle.Close)
	c, err := providers.NewCatalog(providerListConfig(owners...))
	if err != nil {
		t.Fatal(err)
	}
	limit := providerListLimit(t, 1)
	first, err := c.ProviderList(context.Background(), providers.ProviderListRequest{Limit: limit})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(first.NextCursor.String())
	if err != nil {
		t.Fatal(err)
	}
	for index := range raw {
		mutated := slices.Clone(raw)
		mutated[index] ^= 1
		cursor, err := providers.ParseCursor(base64.RawURLEncoding.EncodeToString(mutated))
		if err != nil {
			continue
		}
		result, err := c.ProviderList(context.Background(), providers.ProviderListRequest{Cursor: cursor, Limit: limit})
		var invalid providers.ProviderListInvalidRequestError
		if !errors.As(err, &invalid) || !reflect.DeepEqual(result, providers.ProviderListResult{}) {
			t.Fatal("tampered cursor did not return a typed denial and zero result")
		}
	}
	for _, configure := range []func(*providers.CatalogConfig){
		func(c *providers.CatalogConfig) { c.Providers = c.Providers[:2] },
		func(c *providers.CatalogConfig) { c.CursorKey = []byte(strings.Repeat("z", 32)) },
		func(c *providers.CatalogConfig) {
			c.Providers = slices.Clone(c.Providers)
			c.Providers[1] = otherGoogle
		},
	} {
		config := providerListConfig(owners...)
		configure(&config)
		other, err := providers.NewCatalog(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.ProviderList(context.Background(), providers.ProviderListRequest{Cursor: first.NextCursor, Limit: limit}); err == nil {
			t.Fatal("cursor transferred to another selected snapshot or deployment key")
		}
	}
	if _, err := c.ProviderList(context.Background(), providers.ProviderListRequest{Cursor: first.NextCursor, Limit: providerListLimit(t, 2)}); err == nil {
		t.Fatal("cursor transferred to a different page size")
	}
	if _, err := c.ProviderList(context.Background(), providers.ProviderListRequest{}); err == nil {
		t.Fatal("zero page limit accepted")
	}
	for _, value := range []int{-1, 0, 101} {
		if _, err := providers.NewPageLimit(value); err == nil {
			t.Fatal("out-of-bounds page limit accepted")
		}
	}
	for _, value := range []string{"!", "cursor=", strings.Repeat("a", 513), first.NextCursor.String() + "="} {
		if _, err := providers.ParseCursor(value); err == nil {
			t.Fatal("noncanonical or oversized cursor accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := c.ProviderList(ctx, providers.ProviderListRequest{Limit: limit}); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(result, providers.ProviderListResult{}) {
		t.Fatal("canceled call returned a page")
	}
}

func TestProviderListEmptyCatalogAndInvalidConstruction(t *testing.T) {
	c, err := providers.NewCatalog(providerListConfig())
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.ProviderList(context.Background(), providers.ProviderListRequest{Limit: providerListLimit(t, 1)})
	if err != nil || len(result.Page.Providers()) != 0 || result.NextCursor.String() != "" {
		t.Fatal("empty configuration invented a catalog provider or continuation")
	}
	owners := providerListOwners(t)
	var nilOIDC *oauth.OIDCProvider
	var nilOAuth2 *oauth.OAuth2UserInfoProvider
	for _, config := range []providers.CatalogConfig{
		{}, providerListConfig(nil), providerListConfig(nilOIDC), providerListConfig(nilOAuth2),
		providerListConfig(unselectedProvider{owners[0]}),
		providerListConfig(owners[0], owners[0]),
		{Providers: owners, CursorKey: make([]byte, 32)},
		{Providers: owners, CursorKey: []byte("short")},
	} {
		if catalog, err := providers.NewCatalog(config); catalog != nil || err == nil {
			t.Fatal("invalid or ambiguous catalog configuration accepted")
		}
	}
	if _, err := c.ProviderList(nil, providers.ProviderListRequest{Limit: providerListLimit(t, 1)}); err == nil {
		t.Fatal("nil context accepted")
	}
	var zero providers.CatalogImpl
	if _, err := zero.ProviderList(context.Background(), providers.ProviderListRequest{Limit: providerListLimit(t, 1)}); err == nil {
		t.Fatal("zero catalog returned success")
	}
}

// An arbitrary implementation cannot advertise modes through a catalog label.
type unselectedProvider struct{ oauth.Provider }

func TestProviderListRejectsUnselectedOIDCVariants(t *testing.T) {
	keys := keycloakConfig(t).KeySet
	for _, id := range []string{"google", "apple", "unselected-provider"} {
		owner, err := oauth.NewOIDCProvider(oauth.OIDCConfig{
			ID: id, Version: 1, ClientID: "registered-client", Issuer: "https://issuer.example",
			AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: "https://issuer.example/token",
			RedirectURI: "https://application.example/callback", ClientAuthentication: oauth.PublicClient,
			Scopes: []string{"openid"}, Algorithms: []string{"RS256"}, KeySet: keys,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(owner.Close)
		if catalog, err := providers.NewCatalog(providerListConfig(owner)); catalog != nil || err == nil {
			t.Fatal("unselected generic profile advertised built-in provider support")
		}
	}
}

func TestProviderListStartupKeyAndProfileAreNotDisclosed(t *testing.T) {
	config := providerListConfig(providerListOwners(t)...)
	key := string(config.CursorKey)
	if strings.Contains(fmt.Sprintf("%#v", config), key) {
		t.Fatal("startup formatting disclosed deployment cursor key")
	}
	if raw, err := json.Marshal(config); err == nil || len(raw) != 0 {
		t.Fatal("startup configuration serialized")
	}
	c, err := providers.NewCatalog(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%#v", c), key) {
		t.Fatal("catalog formatting disclosed cursor key")
	}
	if raw, err := json.Marshal(c); err == nil || len(raw) != 0 {
		t.Fatal("catalog key owner serialized")
	}
}

func FuzzProviderListCursor(f *testing.F) {
	github, err := providers.NewGitHub(githubConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(github.Close)
	gitlab, err := providers.NewGitLab(providers.GitLabConfig{Version: 1, ClientID: "registered-client", ClientSecret: []byte("test-only-fuzz-secret"), RedirectURI: "https://application.example/gitlab/callback"})
	if err != nil {
		f.Fatal(err)
	}
	f.Cleanup(gitlab.Close)
	catalog, err := providers.NewCatalog(providerListConfig(github, gitlab))
	if err != nil {
		f.Fatal(err)
	}
	limit, err := providers.NewPageLimit(1)
	if err != nil {
		f.Fatal(err)
	}
	first, err := catalog.ProviderList(context.Background(), providers.ProviderListRequest{Limit: limit})
	if err != nil {
		f.Fatal(err)
	}
	for _, raw := range []string{"", first.NextCursor.String(), "!", strings.Repeat("a", 513), first.NextCursor.String() + "="} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		cursor, err := providers.ParseCursor(raw)
		if err != nil {
			return
		}
		result, err := catalog.ProviderList(context.Background(), providers.ProviderListRequest{Cursor: cursor, Limit: limit})
		if err != nil {
			var invalid providers.ProviderListInvalidRequestError
			if !errors.As(err, &invalid) || !reflect.DeepEqual(result, providers.ProviderListResult{}) {
				t.Fatal("invalid cursor did not return a typed error and zero result")
			}
			return
		}
		if raw != "" && raw != first.NextCursor.String() {
			t.Fatal("unauthenticated cursor selected a catalog position")
		}
		items := result.Page.Providers()
		if len(items) != 1 || !slices.Equal(items[0].SupportedModes(), []providers.ProviderMode{providers.AuthorizationCodeMode}) {
			t.Fatal("cursor escaped the configured finite page and modes")
		}
		if raw == "" && items[0].ID() != "github" || raw != "" && (items[0].ID() != "gitlab" || result.NextCursor.String() != "") {
			t.Fatal("cursor skipped, reordered or continued after page exhaustion")
		}
	})
}
