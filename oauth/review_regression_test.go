package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding"
	"encoding/json"
	"net/http"
	"testing"

	oauth "github.com/faustbrian/go-identity/oauth"
)

func TestSecretBearingProjectionsRefuseSerialization(t *testing.T) {
	provider, _ := liveProvider(t)
	parameters := oauth.AuthorizationParameters{State: testNonce, Nonce: testNonce, PKCEChallenge: verifier(t).Challenge()}
	request, err := provider.Authorization(context.Background(), parameters)
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Tokens.Destroy()
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"configuration", oauth.OIDCConfig{ClientSecret: []byte("secret")}},
		{"authorization-parameters", parameters},
		{"authorization-request", request},
		{"verifier", verifier(t)},
		{"token-set", result.Tokens},
		{"borrowed-tokens", oauth.TokenBytes{AccessToken: []byte("access-secret"), RefreshToken: []byte("refresh-secret"), IDToken: []byte("id-secret")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := json.Marshal(tc.value); err == nil {
				t.Error("secret-bearing projection serialized as JSON")
			}
			marshaler, ok := tc.value.(encoding.TextMarshaler)
			if !ok {
				t.Error("secret-bearing projection lacks text refusal")
				return
			}
			if _, err := marshaler.MarshalText(); err == nil {
				t.Error("secret-bearing projection serialized as text")
			}
		})
	}
}

func TestOIDCTypedNilStandardTransportIsRejectedWithoutPanic(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := providerConfig(t, "https://issuer.example/token", nil, key)
	var transport *http.Transport
	config.HTTPClient = &http.Client{Transport: transport}
	defer func() {
		if recover() != nil {
			t.Error("typed-nil transport panicked")
		}
	}()
	provider, err := oauth.NewOIDCProvider(config)
	if err == nil {
		provider.Close()
		t.Fatal("typed-nil transport accepted")
	}
}
