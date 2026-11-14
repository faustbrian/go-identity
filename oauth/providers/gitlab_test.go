package providers_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/oauth/providers"
)

func TestGitLabCatalogOAuth2ReadUserProfile(t *testing.T) {
	c := providers.GitLabConfig{Version: 1, ClientID: "registered-client", ClientSecret: []byte("test-only-gitlab-secret"), RedirectURI: "https://application.example/gitlab/callback"}
	p, err := providers.NewGitLab(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	facts := p.OAuth2Profile()
	if p.ID() != "gitlab" || facts.Profile.Issuer != "https://gitlab.com" || facts.Profile.ClientAuthentication != oauth.ClientSecretPost || facts.Details.UserInfoEndpoint != "https://gitlab.com/api/v4/user" || facts.Details.SubjectClaim != "id" || facts.Details.SubjectEncoding != oauth.OAuth2PositiveIntegerSubject || facts.Profile.NonceRequired || len(facts.Profile.Algorithms) != 0 {
		t.Fatal("builder did not select the catalog OAuth2/UserInfo facts")
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
	if u.Scheme+"://"+u.Host+u.Path != "https://gitlab.com/oauth/authorize" || u.Query().Get("scope") != "read_user" || u.Query().Has("nonce") || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("builder changed the selected GitLab browser protocol")
	}
}

func TestGitLabClosedConfigurationAndSecretSafety(t *testing.T) {
	base := providers.GitLabConfig{Version: 1, ClientID: "registered-client", ClientSecret: []byte("test-only-gitlab-secret"), RedirectURI: "https://application.example/gitlab/callback"}
	for _, issuer := range []string{"http://gitlab.example", "https://gitlab.example/", "https://user:password@gitlab.example", "https://gitlab.example?query=yes", "https://gitlab.example#fragment", "https://gitlab.example/a/../b", "https://gitlab.example/a/.", "https://gitlab.example//relative", "https://gitlab.example/%2e%2e"} {
		c := base
		c.Issuer = issuer
		if p, err := providers.NewGitLab(c); p != nil || !errors.Is(err, providers.ErrGitLabConfiguration) {
			t.Fatal("unsupported issuer selected")
		}
	}
	if raw, err := json.Marshal(base); err == nil || len(raw) != 0 {
		t.Fatal("secret configuration serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", base), string(base.ClientSecret)) {
		t.Fatal("format disclosed secret")
	}
	c := base
	c.Issuer = "https://gitlab.example/deployment"
	p, err := providers.NewGitLab(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if p.OAuth2Profile().Details.UserInfoEndpoint != "https://gitlab.example/deployment/api/v4/user" {
		t.Fatal("self-managed base lost exact endpoint derivation")
	}
	copy := p.Profile()
	copy.Scopes[0] = "unlisted"
	if p.Profile().Scopes[0] != "read_user" {
		t.Fatal("caller changed immutable scopes")
	}
}

func ExampleNewGitLab() {
	p, err := providers.NewGitLab(providers.GitLabConfig{Version: 1, ClientID: "registered-client", ClientSecret: []byte("example-only-secret"), RedirectURI: "https://application.example/gitlab/callback"})
	if err != nil {
		panic(err)
	}
	defer p.Close()
	fmt.Println(p.ID())
	// Output: gitlab
}
