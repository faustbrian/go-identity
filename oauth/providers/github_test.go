package providers_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/providers"
)

func githubConfig() providers.GitHubConfig {
	return providers.GitHubConfig{Version: 1, ClientID: "registered-client", ClientSecret: []byte("test-only-github-secret"), RedirectURI: "https://application.example/github/callback"}
}

func TestGitHubCatalogOrdinaryOAuthAppProfile(t *testing.T) {
	p, err := providers.NewGitHub(githubConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	facts := p.OAuth2Profile()
	if p.ID() != "github" || facts.Profile.Issuer != "https://github.com" || facts.Profile.ClientAuthentication != oauth.ClientSecretPost || facts.Profile.TokenEndpoint != "https://github.com/login/oauth/access_token" || facts.Details.UserInfoEndpoint != "https://api.github.com/user" || facts.Details.SubjectClaim != "id" || p.OAuth2TokenPolicy() != oauth.OAuth2GitHubOAuthAppPolicy || facts.Profile.NonceRequired || len(facts.Profile.Algorithms) != 0 || !slices.Equal(facts.Profile.Scopes, []string{"read:user", "user:email"}) {
		t.Fatal("builder changed selected ordinary GitHub OAuth-app profile")
	}
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	v, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer v.Destroy()
	authorization, err := p.Authorization(context.Background(), oauth.AuthorizationParameters{State: state, PKCEChallenge: v.Challenge()})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authorization.URL())
	if u.Scheme+"://"+u.Host+u.Path != "https://github.com/login/oauth/authorize" || u.Query().Get("scope") != "read:user user:email" || u.Query().Has("nonce") || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("authorization lost exact endpoint/scopes/S256 or invented nonce")
	}
	copy := p.Profile()
	copy.Scopes[0] = "repo"
	if p.Profile().Scopes[0] != "read:user" {
		t.Fatal("caller changed immutable profile")
	}
}

func TestGitHubConfigurationSecretsAndUnsupportedInputs(t *testing.T) {
	for name, mutate := range map[string]func(*providers.GitHubConfig){
		"zero version":   func(c *providers.GitHubConfig) { c.Version = 0 },
		"missing client": func(c *providers.GitHubConfig) { c.ClientID = "" },
		"missing secret": func(c *providers.GitHubConfig) { c.ClientSecret = nil },
		"insecure route": func(c *providers.GitHubConfig) { c.RedirectURI = "http://app.example/github/callback" },
	} {
		t.Run(name, func(t *testing.T) {
			c := githubConfig()
			mutate(&c)
			if p, err := providers.NewGitHub(c); p != nil || !errors.Is(err, providers.ErrGitHubConfiguration) {
				t.Fatal("invalid startup configuration accepted")
			}
		})
	}
	c := githubConfig()
	if value, err := json.Marshal(c); err == nil || len(value) != 0 {
		t.Fatal("secret configuration serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", c), string(c.ClientSecret)) {
		t.Fatal("format disclosed secret")
	}
	if value, err := c.MarshalText(); err == nil || len(value) != 0 {
		t.Fatal("secret text serialized")
	}
}

func ExampleNewGitHub() {
	p, err := providers.NewGitHub(providers.GitHubConfig{Version: 1, ClientID: "registered-client", ClientSecret: []byte("example-only-secret"), RedirectURI: "https://application.example/github/callback"})
	if err != nil {
		panic(err)
	}
	defer p.Close()
	fmt.Println(p.ID())
	// Output: github
}
