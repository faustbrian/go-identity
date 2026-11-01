package oauth_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	authoidc "github.com/faustbrian/go-authentication/oidc"
)

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func signToken(t *testing.T, private ed25519.PrivateKey, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	message := header + "." + base64.RawURLEncoding.EncodeToString(payload)
	return message + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, []byte(message)))
}

func TestConsumedOIDCValidator(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 14, 0, 0, 0, time.UTC)
	validator, err := authoidc.NewWithKeySet(authoidc.Config{
		Issuer: "https://issuer.example", ClientID: "client", Algorithms: []string{"EdDSA"}, Clock: fixedClock{now},
		NonceValidator: authoidc.NonceValidatorFunc(func(_ context.Context, nonce string) error {
			if nonce != "expected-nonce" {
				return errors.New("nonce rejected")
			}
			return nil
		}),
	}, &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{public}})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": "https://issuer.example", "sub": "provider-subject", "aud": "client", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": "expected-nonce"}
	principal, err := validator.ValidateBearer(context.Background(), signToken(t, private, claims))
	if err != nil || principal.Subject() != "provider-subject" || principal.Issuer() != "https://issuer.example" {
		t.Fatalf("valid token rejected: %v", err)
	}
	for _, field := range []string{"iss", "aud", "azp", "nonce", "exp", "iat"} {
		t.Run(field, func(t *testing.T) {
			bad := make(map[string]any, len(claims))
			for k, v := range claims {
				bad[k] = v
			}
			switch field {
			case "exp":
				bad[field] = now.Add(-time.Hour).Unix()
			case "iat":
				bad[field] = now.Add(time.Hour).Unix()
			default:
				bad[field] = "wrong"
			}
			if _, err := validator.ValidateBearer(context.Background(), signToken(t, private, bad)); err == nil {
				t.Fatal("invalid token accepted")
			}
		})
	}
}
