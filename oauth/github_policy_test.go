package oauth_test

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/oauth"
)

func githubOAuth2Config() oauth.OAuth2UserInfoConfig {
	return oauth.OAuth2UserInfoConfig{ID: "github", Version: 1, Issuer: "https://github.com", AuthorizationEndpoint: "https://github.com/login/oauth/authorize", TokenEndpoint: "https://github.com/login/oauth/access_token", UserInfoEndpoint: "https://api.github.com/user", RedirectURI: "https://app.example/github/callback", ClientID: "registered-client", ClientSecret: []byte("test-only-client-secret"), ClientAuthentication: oauth.ClientSecretPost, Scopes: []string{"read:user", "user:email"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject, ProofLifetime: 20 * time.Second}
}

func TestGitHubCallbackRemainsConsumableByNativeRequestShapes(t *testing.T) {
	c := githubOAuth2Config()
	p, err := oauth.NewOAuth2UserInfoProviderWithPolicy(c, oauth.OAuth2GitHubOAuthAppPolicy)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, response := range []string{"code=test-only-code", "error=access_denied"} {
		callback, err := oauth.ParseOAuth2QueryCallbackWithPolicy(context.Background(), response+"&state="+state, c.RedirectURI, p.OAuth2Profile(), p.OAuth2TokenPolicy())
		if err != nil {
			t.Fatal(err)
		}
		defer callback.Destroy()
		browser := auth.NewBearerCredential(base64.RawURLEncoding.EncodeToString(make([]byte, 32)))
		if err := (oauth.CallbackRequest{Callback: callback, TenantID: "tenant-a", Session: browser, Origin: "https://app.example", Network: "192.0.2.1"}).Validate(); err != nil {
			t.Fatal("selected callback cannot enter native link request", err)
		}
		if err := (oauth.SigninCallbackRequest{Callback: callback, TenantID: "tenant-a", FlowCookie: browser, Origin: "https://app.example", Network: "192.0.2.1", Device: "browser-a"}).Validate(); err != nil {
			t.Fatal("selected callback cannot enter native signin request", err)
		}
	}
}

func TestGitHubOAuth2PolicyIsExplicitAndCallbackBound(t *testing.T) {
	c := githubOAuth2Config()
	if p, err := oauth.NewOAuth2UserInfoProvider(c); err == nil {
		p.Close()
		t.Fatal("strict default silently admitted cross-origin UserInfo")
	}
	p, err := oauth.NewOAuth2UserInfoProviderWithPolicy(c, oauth.OAuth2GitHubOAuthAppPolicy)
	if err != nil {
		t.Fatal("explicit GitHub OAuth-app profile unavailable", err)
	}
	defer p.Close()
	if p.OAuth2TokenPolicy() != oauth.OAuth2GitHubOAuthAppPolicy || p.OAuth2Profile().Validate() == nil {
		t.Fatal("selected policy weakened strict profile validation")
	}
	if _, err := oauth.NewProviderRegistry(p); err != nil {
		t.Fatal("selected provider cannot enter existing native registry", err)
	}
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	query := "code=test-only-code&state=" + state
	if out, err := oauth.ParseOAuth2QueryCallback(context.Background(), query, c.RedirectURI, p.OAuth2Profile()); err == nil {
		out.Destroy()
		t.Fatal("old callback entrypoint silently selected new policy")
	}
	out, err := oauth.ParseOAuth2QueryCallbackWithPolicy(context.Background(), query, c.RedirectURI, p.OAuth2Profile(), p.OAuth2TokenPolicy())
	if err != nil {
		t.Fatal(err)
	}
	defer out.Destroy()
	if out.OAuth2TokenPolicy() != oauth.OAuth2GitHubOAuthAppPolicy {
		t.Fatal("parsed callback lost immutable token policy")
	}
	for name, mutate := range map[string]func(*oauth.OAuth2UserInfoConfig){
		"foreign issuer":   func(c *oauth.OAuth2UserInfoConfig) { c.Issuer = "https://evil.example" },
		"foreign resource": func(c *oauth.OAuth2UserInfoConfig) { c.UserInfoEndpoint = "https://elsewhere.example/user" },
		"foreign token":    func(c *oauth.OAuth2UserInfoConfig) { c.TokenEndpoint = "https://api.github.com/token" },
		"scope expansion":  func(c *oauth.OAuth2UserInfoConfig) { c.Scopes = append(c.Scopes, "repo") },
		"fixed TLS peer name": func(c *oauth.OAuth2UserInfoConfig) {
			c.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "github.com"}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := githubOAuth2Config()
			mutate(&changed)
			if got, err := oauth.NewOAuth2UserInfoProviderWithPolicy(changed, oauth.OAuth2GitHubOAuthAppPolicy); err == nil {
				got.Close()
				t.Fatal("selected policy admitted a different protocol contract")
			}
		})
	}
}
