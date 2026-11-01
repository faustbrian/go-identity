package oauth_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-identity/oauth"
)

var testNow = time.Date(2026, 11, 1, 14, 0, 0, 0, time.UTC)
var testNonce = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
var testVerifier = strings.Repeat("v", 64)

func esToken(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := crypto.SHA256.New()
	_, _ = digest.Write([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return message + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func oidcClaims() map[string]any {
	return map[string]any{"iss": "https://issuer.example", "sub": "provider-subject", "aud": "client:+ secret", "iat": testNow.Unix(), "exp": testNow.Add(time.Minute).Unix(), "nonce": testNonce}
}

func providerConfig(t *testing.T, endpoint string, client *http.Client, key *ecdsa.PrivateKey) oauth.OIDCConfig {
	t.Helper()
	return oauth.OIDCConfig{ID: "generic", Version: 1, Issuer: "https://issuer.example", AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: endpoint, RedirectURI: "https://application.example/callback", ClientID: "client:+ secret", ClientSecret: []byte("configuration-secret"), ClientAuthentication: oauth.ClientSecretBasic, Scopes: []string{"openid", "profile"}, Algorithms: []string{"ES256"}, KeySet: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, HTTPClient: client, Clock: fixedClock{testNow}, ClockSkew: time.Minute, Timeout: time.Second}
}

func callback(t *testing.T) identity.OAuthCallbackInput {
	t.Helper()
	input, err := identity.NewOAuthCallbackInput([]byte(" exact +/=: code "), testNonce, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Destroy)
	return input
}

func verifier(t *testing.T) oauth.PKCEVerifier {
	t.Helper()
	input, err := oauth.NewPKCEVerifier([]byte(testVerifier))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Destroy)
	return input
}

func TestOIDCProviderPublicExchange(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.RequestURI() != "/token" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("wrong token request")
		}
		user, password, ok := r.BasicAuth()
		if !ok || user != url.QueryEscape("client:+ secret") || password != url.QueryEscape("configuration-secret") {
			t.Error("wrong exact client authentication")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			t.Error(err)
		}
		if len(values) != 4 || values.Get("grant_type") != "authorization_code" || values.Get("code") != " exact +/=: code " || values.Get("code_verifier") != testVerifier || values.Get("redirect_uri") != "https://application.example/callback" {
			t.Error("wrong exchange form")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "refresh_token": "refresh-secret", "id_token": esToken(t, key, oidcClaims()), "token_type": "Bearer", "expires_in": 3600})
	}))
	defer server.Close()
	provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL+"/token", server.Client(), key))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if calls.Load() != 0 {
		t.Fatal("constructor performed I/O")
	}
	request, err := provider.Authorization(context.Background(), oauth.AuthorizationParameters{State: testNonce, Nonce: testNonce, PKCEChallenge: verifier(t).Challenge()})
	if err != nil {
		t.Fatal(err)
	}
	authorize, err := url.Parse(request.URL())
	if err != nil {
		t.Fatal(err)
	}
	q := authorize.Query()
	if authorize.Host != "issuer.example" || len(q) != 9 || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("response_mode") != "query" || q.Get("scope") != "openid profile" || q.Get("redirect_uri") != "https://application.example/callback" || q.Get("client_id") != "client:+ secret" || q.Get("state") != testNonce || q.Get("nonce") != testNonce {
		t.Fatal("wrong authorization request")
	}
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	if calls.Load() != 1 || result.Identity.ProviderID() != "generic" || result.Identity.Subject() != "provider-subject" || result.Identity.Issuer() != "https://issuer.example" {
		t.Fatal("missing verified identity")
	}
	if when, present := result.Identity.AuthenticationTime(); present || !when.IsZero() {
		t.Fatal("iat substituted for absent authentication time")
	}
	if !result.Identity.IDTokenIssuedAt().Equal(testNow) || !result.Identity.IDTokenExpiresAt().Equal(testNow.Add(time.Minute)) {
		t.Fatal("ID-token source proof lifetime lost")
	}
	var borrowed []byte
	err = result.Tokens.Use(context.Background(), func(_ context.Context, secrets oauth.TokenBytes) error {
		borrowed = secrets.AccessToken
		if string(secrets.AccessToken) != "access-secret" || string(secrets.RefreshToken) != "refresh-secret" || len(secrets.IDToken) == 0 {
			t.Fatal("wrong token custody")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range borrowed {
		if b != 0 {
			t.Fatal("borrow not cleared")
		}
	}
	if !result.Tokens.ExpiresAt().Equal(testNow.Add(time.Hour)) {
		t.Fatal("wrong token expiry")
	}
	for _, value := range []any{provider, providerConfig(t, server.URL, server.Client(), key), result.Tokens, request, verifier(t)} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			rendered := fmt.Sprintf(verb, value)
			for _, secret := range []string{"configuration-secret", "access-secret", "refresh-secret", testVerifier, testNonce} {
				if strings.Contains(rendered, secret) {
					t.Fatal("diagnostic secret disclosure")
				}
			}
		}
	}
	if _, err := json.Marshal(result.Tokens); err == nil {
		t.Fatal("token serialized")
	}
}

func TestOIDCProviderRejectsInvalidProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"iss", "aud", "azp", "nonce", "iat", "exp", "signature"} {
		t.Run(field, func(t *testing.T) {
			claims := oidcClaims()
			switch field {
			case "iat":
				claims[field] = testNow.Add(time.Hour).Unix()
			case "exp":
				claims[field] = testNow.Add(-time.Hour).Unix()
			case "signature":
			default:
				claims[field] = "wrong"
			}
			token := esToken(t, key, claims)
			if field == "signature" {
				token = token[:len(token)-4] + "AAAA"
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "secret", "id_token": token, "token_type": "Bearer", "expires_in": 10})
			}))
			defer server.Close()
			provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL, server.Client(), key))
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			var failure *oauth.Error
			if !errors.As(err, &failure) || failure.Kind() != oauth.InvalidProof {
				t.Fatalf("wrong proof result: %v", err)
			}
			if result.Identity.Subject() != "" || result.Tokens.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
				t.Fatal("invalid proof returned custody")
			}
		})
	}
}
