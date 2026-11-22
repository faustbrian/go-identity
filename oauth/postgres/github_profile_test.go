package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/risk"
)

func nativeGitHubProvider(t *testing.T) *oauth.OAuth2UserInfoProvider {
	t.Helper()
	p, err := oauth.NewOAuth2UserInfoProviderWithPolicy(oauth.OAuth2UserInfoConfig{ID: "github", Version: 1, Issuer: "https://github.com", AuthorizationEndpoint: "https://github.com/login/oauth/authorize", TokenEndpoint: "https://github.com/login/oauth/access_token", UserInfoEndpoint: "https://api.github.com/user", RedirectURI: "https://app.example/github/callback", ClientID: "registered-client", ClientSecret: []byte("test-only-client-secret"), ClientAuthentication: oauth.ClientSecretPost, Scopes: []string{"read:user", "user:email"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject}, oauth.OAuth2GitHubOAuthAppPolicy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestGitHubNativeFullPolicyIsAuthenticatedInLinkAndSigninState(t *testing.T) {
	provider := nativeGitHubProvider(t)
	profile := provider.OAuth2Profile()
	details := map[string]oauth.OAuth2UserInfoDetails{"github": profile.Details}
	policies := map[string]oauth.OAuth2TokenPolicy{"github": oauth.OAuth2GitHubOAuthAppPolicy}
	t.Run("link", func(t *testing.T) {
		p, _, _, _ := rpCallbackInputFixture(t)
		p.input.Provider = "github"
		p.service.profiles = map[string]oauth.ProviderProfile{"github": profile.Profile}
		p.service.oauth2Profiles, p.service.oauth2TokenPolicies = details, policies
		wire, err := p.generateOutput(context.Background(), 1)
		if err != nil {
			t.Fatal(err)
		}
		out, _, _, err := p.restoreOutput(context.Background(), 1, wire)
		if err != nil || out.Binding.OAuth2TokenPolicy != oauth.OAuth2GitHubOAuthAppPolicy {
			t.Fatal("link state lost selected token policy", err)
		}
		p.service.oauth2TokenPolicies = nil
		if _, _, _, err := p.restoreOutput(context.Background(), 1, wire); err == nil {
			t.Fatal("changed policy adopted existing link state")
		}
	})
	t.Run("signin", func(t *testing.T) {
		p := signinOutputFixture(t)
		p.input.Provider = "github"
		p.service.profiles = map[string]oauth.ProviderProfile{"github": profile.Profile}
		p.service.oauth2Profiles, p.service.oauth2TokenPolicies = details, policies
		wire, err := p.generateOutput(context.Background(), 1, risk.AuthenticationAdmission{})
		if err != nil {
			t.Fatal(err)
		}
		out, _, _, err := p.restoreOutput(context.Background(), 1, wire)
		if err != nil || out.Binding.OAuth2TokenPolicy != oauth.OAuth2GitHubOAuthAppPolicy {
			t.Fatal("signin state lost selected token policy", err)
		}
		p.service.oauth2TokenPolicies = nil
		if _, _, _, err := p.restoreOutput(context.Background(), 1, wire); err == nil {
			t.Fatal("changed policy adopted existing signin state")
		}
	})
}

func TestGitHubNativeAbsentTokenExpiryIsSelectedNotGeneric(t *testing.T) {
	s, b, tokens := rpVaultFixture(t, true)
	tokens.Destroy()
	provider := nativeGitHubProvider(t)
	profile := provider.OAuth2Profile()
	s.profiles = map[string]oauth.ProviderProfile{"github": profile.Profile}
	s.oauth2Profiles = map[string]oauth.OAuth2UserInfoDetails{"github": profile.Details}
	s.oauth2TokenPolicies = map[string]oauth.OAuth2TokenPolicy{"github": oauth.OAuth2GitHubOAuthAppPolicy}
	b.ProviderID, b.Issuer, b.ClientID, b.ConfigurationVersion = "github", profile.Profile.Issuer, profile.Profile.ClientID, profile.Profile.Version
	p := rpPreparedTokenSet{Schema: 1, Binding: b, RequestedScopes: profile.Profile.Scopes, GrantedScopes: profile.Profile.Scopes, ScopeReported: true, ReceivedAt: time.Date(2026, 11, 14, 10, 0, 0, 123456789, time.UTC), Version: 1, SocialConnectionVersion: 1}
	if _, err := s.tokenVaultMetadata(p); err != nil {
		t.Fatal("honestly absent GitHub expiry rejected", err)
	}
	before, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var restored rpPreparedTokenSet
	if json.Unmarshal(before, &restored) != nil || !reflect.DeepEqual(p, restored) || !restored.AccessExpiresAt.IsZero() {
		t.Fatal("restore renewed absent token expiry")
	}
	s.oauth2TokenPolicies = nil
	if _, err := s.tokenVaultMetadata(p); err == nil {
		t.Fatal("strict profile accepted absent expiry")
	}
}

func TestGitHubOptionalExpiryMigrationIsForwardAndPhased(t *testing.T) {
	history, err := (TokenVaultOptionalExpiryMigrationSource{Schema: "oauth_rp", Version: 102}).Load(context.Background())
	if err != nil || len(history) != 2 {
		t.Fatal("optional-expiry forward history unavailable", err)
	}
	if history[0].Version() != 102 || history[1].Version() != 103 || history[0].DownSQL() != "" || history[1].DownSQL() != "" {
		t.Fatal("migration replaced history or exposed destructive downgrade")
	}
}
