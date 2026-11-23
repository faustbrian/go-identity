package oauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

func sharedRefreshFixture(t *testing.T, handler http.HandlerFunc) (*oauth.SharedOAuth2UserInfoProvider, *oauth.OAuth2RefreshProvider) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	config := sharedOAuth2UserInfoConfig(server, oauth2Clock{testNow})
	provider, err := oauth.NewSharedOAuth2UserInfoProvider(config, []string{"email"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	adapter, err := oauth.NewSharedOAuth2RefreshProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	return provider, adapter
}

func sharedStoredRefresh(t *testing.T, profile oauth.ProviderProfile, scopes []string) oauth.RefreshToken {
	t.Helper()
	input, err := oauth.NewRefreshToken([]byte("shared-original +/=: refresh"), profile, scopes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Destroy)
	return input
}

func TestSharedOAuth2RefreshTLSOriginalGrantScopesAndRotation(t *testing.T) {
	for _, rotated := range []bool{false, true} {
		t.Run(fmt.Sprint("rotated=", rotated), func(t *testing.T) {
			var calls atomic.Int32
			provider, adapter := sharedRefreshFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				want := url.Values{
					"grant_type": {"refresh_token"}, "refresh_token": {"shared-original +/=: refresh"},
					"client_id": {"registered-client"}, "client_secret": {"test-only-client-secret"},
				}
				if r.TLS == nil || r.Method != http.MethodPost || r.URL.RequestURI() != "/token" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.ParseForm() != nil || !reflect.DeepEqual(r.PostForm, want) {
					t.Error("shared refresh lost exact TLS endpoint, opaque token or credential binding")
				}
				response := map[string]any{"access_token": "shared-new-access", "token_type": "Bearer", "expires_in": 60}
				if rotated {
					response["refresh_token"] = "shared-rotated-refresh"
					response["scope"] = "profile"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(response)
			})
			originalScopes := []string{"profile"}
			if rotated {
				originalScopes = []string{"profile", "email"}
			}
			input := sharedStoredRefresh(t, provider.Profile(), originalScopes)
			result, err := adapter.Refresh(t.Context(), input)
			if err != nil {
				t.Fatal(err)
			}
			defer result.Tokens.Destroy()
			if calls.Load() != 1 || !reflect.DeepEqual(result.Tokens.RequestedScopes(), originalScopes) || !reflect.DeepEqual(result.Tokens.GrantedScopes(), []string{"profile"}) || result.Tokens.ScopeReported() != rotated || !result.Tokens.ReceivedAt().Equal(testNow) || !result.Tokens.ExpiresAt().Equal(testNow.Add(time.Minute)) {
				t.Fatal("shared refresh changed original grant scopes, lost expiry evidence or performed additional I/O")
			}
			wantRotation := oauth.RetainOriginalRefreshToken
			wantRefresh := ""
			if rotated {
				wantRotation, wantRefresh = oauth.RotatedRefreshToken, "shared-rotated-refresh"
			}
			if result.Rotation != wantRotation {
				t.Fatal("shared refresh lost rotation disposition")
			}
			if err := result.Tokens.Use(t.Context(), func(_ context.Context, value oauth.TokenBytes) error {
				if string(value.AccessToken) != "shared-new-access" || string(value.RefreshToken) != wantRefresh || len(value.IDToken) != 0 {
					t.Error("shared refresh returned wrong tokens or invented OIDC evidence")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSharedOAuth2RefreshExactProfileAndCustodyDenyBeforeIO(t *testing.T) {
	var calls atomic.Int32
	provider, adapter := sharedRefreshFixture(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	for _, test := range []struct {
		name   string
		mutate func(*oauth.ProviderProfile)
	}{
		{"provider", func(p *oauth.ProviderProfile) { p.ID = "foreign" }},
		{"version", func(p *oauth.ProviderProfile) { p.Version++ }},
		{"client", func(p *oauth.ProviderProfile) { p.ClientID = "foreign-client" }},
		{"redirect", func(p *oauth.ProviderProfile) { p.RedirectURI = "https://other.example/shared/callback" }},
		{"token endpoint", func(p *oauth.ProviderProfile) { p.TokenEndpoint += "/other" }},
		{"authorization endpoint", func(p *oauth.ProviderProfile) { p.AuthorizationEndpoint += "/other" }},
		{"configured scopes", func(p *oauth.ProviderProfile) { p.Scopes = []string{"profile"} }},
		{"issuer", func(p *oauth.ProviderProfile) {
			p.Issuer = "https://foreign.example"
			p.AuthorizationEndpoint = p.Issuer + "/authorize"
			p.TokenEndpoint = p.Issuer + "/token"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			profile := provider.Profile()
			test.mutate(&profile)
			result, err := adapter.Refresh(t.Context(), sharedStoredRefresh(t, profile, []string{"profile"}))
			defer result.Tokens.Destroy()
			refreshKind(t, err, oauth.InvalidInput)
			if result.Rotation != "" {
				t.Fatal("denied profile returned rotation evidence")
			}
		})
	}
	input := sharedStoredRefresh(t, provider.Profile(), []string{"profile"})
	_, err := adapter.Refresh(nil, input)
	refreshKind(t, err, oauth.InvalidInput)
	_, err = adapter.Refresh(t.Context(), oauth.RefreshToken{})
	refreshKind(t, err, oauth.InvalidInput)
	alias := input
	input.Destroy()
	_, err = adapter.Refresh(t.Context(), alias)
	refreshKind(t, err, oauth.InvalidInput)
	if calls.Load() != 0 {
		t.Fatal("denied shared profile or custody exposed credentials")
	}
}

func TestSharedOAuth2RefreshBorrowsProviderLifetime(t *testing.T) {
	var calls atomic.Int32
	provider, adapter := sharedRefreshFixture(t, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	input := sharedStoredRefresh(t, provider.Profile(), []string{"profile"})
	provider.Close()
	_, err := adapter.Refresh(t.Context(), input)
	refreshKind(t, err, oauth.InvalidInput)
	for _, absent := range []*oauth.SharedOAuth2UserInfoProvider{nil, {}, provider} {
		selected, err := oauth.NewSharedOAuth2RefreshProvider(absent)
		refreshKind(t, err, oauth.InvalidInput)
		if selected != nil {
			t.Fatal("nil, zero or closed shared provider gained refresh capability")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("closed shared provider released credentials")
	}
}
