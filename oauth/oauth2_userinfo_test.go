package oauth_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
)

type oauth2Clock struct{ now time.Time }

func (c oauth2Clock) Now() time.Time { return c.now }

func TestOAuth2UserInfoOriginalTokenProofWithoutInventedOIDCClaims(t *testing.T) {
	now := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	var tokenCalls, userCalls atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/oauth/token":
			tokenCalls.Add(1)
			if r.Method != "POST" || r.Header.Get("Authorization") != "" || r.ParseForm() != nil || len(r.PostForm) != 6 || r.PostForm.Get("client_id") != "registered-client" || r.PostForm.Get("client_secret") != "test-only-client-secret" || r.PostForm.Get("code_verifier") != strings.Repeat("v", 64) {
				t.Error("token request escaped POST credentials/S256 binding")
				w.WriteHeader(400)
				return
			}
			fmt.Fprint(w, `{"access_token":"test-only-access-token","token_type":"Bearer","expires_in":60,"scope":"read_user"}`)
		case "/api/v4/user":
			userCalls.Add(1)
			if r.Method != "GET" || r.Header.Get("Authorization") != "Bearer test-only-access-token" || r.URL.RawQuery != "" {
				t.Error("UserInfo request was not exactly bearer-bound")
				w.WriteHeader(400)
				return
			}
			fmt.Fprint(w, `{"id":42,"username":"display-only","email":"not-identity@example.invalid"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := oauth.OAuth2UserInfoConfig{ID: "gitlab", Version: 1, Issuer: server.URL, AuthorizationEndpoint: server.URL + "/oauth/authorize", TokenEndpoint: server.URL + "/oauth/token", UserInfoEndpoint: server.URL + "/api/v4/user", ClientID: "registered-client", ClientSecret: []byte("test-only-client-secret"), ClientAuthentication: oauth.ClientSecretPost, RedirectURI: "https://application.example/gitlab/callback", Scopes: []string{"read_user"}, SubjectClaim: "id", SubjectEncoding: oauth.OAuth2PositiveIntegerSubject, Clock: oauth2Clock{now.In(time.FixedZone("test-offset", 3*60*60))}, HTTPClient: server.Client(), Timeout: time.Second}
	p, err := oauth.NewOAuth2UserInfoProvider(c)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var existing oauth.Provider = p
	profile := existing.Profile()
	state := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	verifier, err := oauth.NewPKCEVerifier([]byte(strings.Repeat("v", 64)))
	if err != nil {
		t.Fatal(err)
	}
	defer verifier.Destroy()
	t.Run("authorization rejects unsupported nonce", func(t *testing.T) {
		if _, err := p.Authorization(context.Background(), oauth.AuthorizationParameters{State: state, Nonce: state, PKCEChallenge: verifier.Challenge()}); err == nil {
			t.Fatal("nonce-free provider silently accepted a nonce")
		}
	})
	authorization, err := p.Authorization(context.Background(), oauth.AuthorizationParameters{State: state, PKCEChallenge: verifier.Challenge()})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authorization.URL())
	if u.Query().Get("nonce") != "" || u.Query().Has("nonce") || u.Query().Get("scope") != "read_user" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("OAuth2 authorization acquired OIDC claims or lost S256")
	}
	query := (url.Values{"code": {"test-only-code"}, "state": {state}}).Encode()
	if bad, err := oauth.ParseOAuth2QueryCallback(context.Background(), query, "https://application.example/other/callback", p.OAuth2Profile()); err == nil {
		bad.Destroy()
		t.Fatal("foreign received callback route was accepted")
	}
	callback, err := oauth.ParseOAuth2QueryCallback(context.Background(), query, c.RedirectURI, p.OAuth2Profile())
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Destroy()
	input, ok := callback.Input()
	if !ok {
		t.Fatal("OAuth2 callback lost code custody")
	}
	t.Run("exchange rejects unsupported nonce", func(t *testing.T) {
		unexpected, err := p.Exchange(context.Background(), input, verifier, state)
		defer unexpected.Tokens.Destroy()
		if err == nil {
			t.Fatal("nonce-free provider silently ignored an exchange nonce")
		}
	})
	out, err := p.Exchange(context.Background(), input, verifier, "")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Tokens.Destroy()
	if tokenCalls.Load() != 1 || userCalls.Load() != 1 || out.Identity.Issuer() != server.URL || out.Identity.ProviderID() != "gitlab" || out.Identity.Subject() != "42" {
		t.Fatal("OAuth2 proof lost its provider/token-bound stable subject")
	}
	if !out.Identity.IDTokenIssuedAt().IsZero() || !out.Identity.IDTokenExpiresAt().IsZero() {
		t.Fatal("OAuth2 proof manufactured ID-token claims")
	}
	if _, present := out.Identity.AuthenticationTime(); present {
		t.Fatal("UserInfo observation was presented as fresh provider authentication")
	}
	if !out.Identity.EvidenceExpiresAt().Equal(now.Add(20 * time.Second)) {
		t.Fatal("OAuth2 evidence lost its original bounded observation expiry")
	}
	if out.Identity.EvidenceExpiresAt().Location() != time.UTC {
		t.Fatal("OAuth2 observation expiry is not native-consumable canonical UTC")
	}
	if _, err := oauth.ParseQueryCallback(context.Background(), query, profile); err == nil {
		t.Fatal("strict OIDC parser silently changed its profile")
	}
}
