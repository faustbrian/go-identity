package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func TestZeroOIDCProviderDeniesAndCloses(t *testing.T) {
	var provider oauth.OIDCProvider
	request, err := provider.Authorization(context.Background(), oauth.AuthorizationParameters{State: testNonce, Nonce: testNonce, PKCEChallenge: verifier(t).Challenge()})
	if err == nil || request.URL() != "" {
		t.Error("zero provider emitted authorization request")
	}
	func() {
		defer func() {
			if recover() != nil {
				t.Error("zero Close panicked")
			}
		}()
		provider.Close()
		provider.Close()
	}()
}

func hashBinding(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

func TestOIDCOptionalHashClaimsBindExactTokensAndCode(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		alter   func(map[string]any)
		invalid bool
	}{
		{"omitted", func(map[string]any) {}, false},
		{"explicit-auth-time", func(c map[string]any) { c["auth_time"] = int64(0) }, false},
		{"fractional-token-dates", func(c map[string]any) {
			c["iat"] = json.Number(fmt.Sprint(testNow.Unix()) + ".125")
			c["exp"] = json.Number(fmt.Sprint(testNow.Add(time.Minute).Unix()) + ".875")
		}, false},
		{"valid", func(c map[string]any) {
			c["at_hash"] = hashBinding("access-secret")
			c["c_hash"] = hashBinding(" exact +/=: code ")
		}, false},
		{"wrong-access", func(c map[string]any) { c["at_hash"] = hashBinding("other") }, true},
		{"wrong-code", func(c map[string]any) { c["c_hash"] = hashBinding("exact +/=: code") }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := oidcClaims()
			tc.alter(claims)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access-secret", "id_token": esToken(t, key, claims), "token_type": "Bearer", "expires_in": 60})
			}))
			defer server.Close()
			provider, err := oauth.NewOIDCProvider(providerConfig(t, server.URL, server.Client(), key))
			if err != nil {
				t.Fatal(err)
			}
			defer provider.Close()
			result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
			defer result.Tokens.Destroy()
			if !tc.invalid {
				if err != nil {
					t.Fatal("compliant optional hash claims rejected")
				}
				when, present := result.Identity.AuthenticationTime()
				if tc.name == "fractional-token-dates" && (!result.Identity.IDTokenIssuedAt().Equal(testNow.Add(125*time.Millisecond)) || !result.Identity.IDTokenExpiresAt().Equal(testNow.Add(time.Minute+875*time.Millisecond))) {
					t.Fatal("accepted numeric-date metadata changed")
				}
				if tc.name == "explicit-auth-time" {
					if !present || !when.Equal(time.Unix(0, 0)) {
						t.Fatal("explicit authentication time lost")
					}
				} else if present || !when.IsZero() {
					t.Fatal("absent authentication time fabricated")
				}
				return
			}
			var failure *oauth.Error
			if !errors.As(err, &failure) || failure.Kind() != oauth.InvalidProof {
				t.Fatal("wrong token/code hash accepted")
			}
		})
	}
}

func TestProviderProfileSnapshotsTrustedConfiguration(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := providerConfig(t, "https://issuer.example/token", nil, key)
	provider, err := oauth.NewOIDCProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	config.Scopes[0] = "attacker"
	config.Algorithms[0] = "none"
	clear(config.ClientSecret)
	profile := provider.Profile()
	if profile.ID != "generic" || profile.Version != 1 || profile.Issuer != "https://issuer.example" || profile.ClientID != "client:+ secret" || profile.RedirectURI != "https://application.example/callback" || profile.AuthorizationEndpoint != "https://issuer.example/authorize" || profile.TokenEndpoint != "https://issuer.example/token" || profile.ResponseMode != "query" || profile.PKCEMethod != "S256" || !profile.NonceRequired || profile.StateBytes != 32 || profile.NonceBytes != 32 || profile.Timeout != time.Second || profile.ClockSkew != time.Minute || profile.MaxResponseBytes != 65536 || profile.MaxTokenBytes != 16384 || profile.MaxCodeBytes != 4096 || profile.ClientAuthentication != oauth.ClientSecretBasic {
		t.Fatal("profile lost exact effective configuration")
	}
	profile.Scopes[0] = "changed"
	profile.Algorithms[0] = "changed"
	if provider.Profile().Scopes[0] != "openid" || provider.Profile().Algorithms[0] != "ES256" {
		t.Fatal("mutable profile changed provider")
	}
	registry, err := oauth.NewProviderRegistry(provider)
	if err != nil {
		t.Fatal(err)
	}
	if found, ok := registry.Lookup("generic"); !ok || found != provider {
		t.Fatal("configured provider missing")
	}
	if _, ok := registry.Lookup("Generic"); ok {
		t.Fatal("registry normalized provider ID")
	}
	if _, err := oauth.NewProviderRegistry(provider, provider); err == nil {
		t.Fatal("duplicate provider accepted")
	}
	config = providerConfig(t, "https://issuer.example/token", nil, key)
	config.Version = 0
	if p, err := oauth.NewOIDCProvider(config); err == nil {
		p.Close()
		t.Fatal("zero version accepted")
	}
}
