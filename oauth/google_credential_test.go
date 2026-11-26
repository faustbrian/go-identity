package oauth_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/faustbrian/go-identity/oauth"
)

func googleCredentialProvider(t *testing.T, key *ecdsa.PrivateKey) (*oauth.OIDCProvider, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	client := &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unexpected token endpoint call")
	}}}
	config := providerConfig(t, "https://token.example/token", client, key)
	config.Issuer = googleIssuer
	provider, err := oauth.NewGoogleAccountsProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	return provider, &calls
}

func TestGoogleCredentialVerifiedIdentityWithoutExchange(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, issuer := range []string{googleIssuer, "accounts.google.com"} {
		for _, authenticationTime := range []bool{false, true} {
			t.Run(fmt.Sprintf("issuer=%s/auth_time=%t", issuer, authenticationTime), func(t *testing.T) {
				provider, calls := googleCredentialProvider(t, key)
				claims := oidcClaims()
				claims["iss"], claims["sub"] = issuer, "exact Google subject:+ /"
				if authenticationTime {
					claims["auth_time"] = testNow.Add(-time.Minute).Unix()
				}
				token := []byte(esToken(t, key, claims))
				original := bytes.Clone(token)
				got, err := provider.VerifyGoogleCredential(context.Background(), oauth.GoogleCredential{IDToken: token}, oauth.GoogleCredentialNonce{OriginalNonce: testNonce})
				if err != nil {
					t.Fatal(err)
				}
				if got.ProviderID() != provider.ID() || got.Issuer() != googleIssuer || got.Subject() != claims["sub"] {
					t.Fatal("missing strict Google identity")
				}
				when, present := got.AuthenticationTime()
				if present != authenticationTime || authenticationTime && !when.Equal(testNow.Add(-time.Minute)) || !authenticationTime && !when.IsZero() {
					t.Fatal("iat replaced absent auth_time or explicit auth_time was lost")
				}
				if !got.IDTokenIssuedAt().Equal(testNow) || !got.IDTokenExpiresAt().Equal(testNow.Add(time.Minute)) || !got.EvidenceExpiresAt().Equal(testNow.Add(time.Minute)) {
					t.Fatal("source evidence lifetime changed")
				}
				if calls.Load() != 0 || !bytes.Equal(token, original) {
					t.Fatal("verification exchanged tokens or mutated borrowed credential")
				}
			})
		}
	}
}

func TestGoogleCredentialRejectsInvalidProof(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		change func(map[string]any)
		signer *ecdsa.PrivateKey
	}{
		{"issuer", func(c map[string]any) { c["iss"] = "https://other.example" }, key},
		{"audience", func(c map[string]any) { c["aud"] = "other-client" }, key},
		{"authorized party", func(c map[string]any) { c["azp"] = "other-client" }, key},
		{"multiple audiences without azp", func(c map[string]any) { c["aud"] = []string{"client:+ secret", "other-client"} }, key},
		{"nonce", func(c map[string]any) { c["nonce"] = strings.Repeat("x", 43) }, key},
		{"missing nonce", func(c map[string]any) { delete(c, "nonce") }, key},
		{"subject", func(c map[string]any) { c["sub"] = "" }, key},
		{"expired", func(c map[string]any) { c["exp"] = testNow.Add(-2 * time.Minute).Unix() }, key},
		{"future issuance", func(c map[string]any) { c["iat"] = testNow.Add(2 * time.Minute).Unix() }, key},
		{"not before", func(c map[string]any) { c["nbf"] = testNow.Add(2 * time.Minute).Unix() }, key},
		{"signature", func(map[string]any) {}, wrongKey},
		{"access hash without companion", func(c map[string]any) { c["at_hash"] = googleHash("access-secret") }, key},
		{"code hash without companion", func(c map[string]any) { c["c_hash"] = googleHash("code-secret") }, key},
		{"null access hash", func(c map[string]any) { c["at_hash"] = nil }, key},
		{"null code hash", func(c map[string]any) { c["c_hash"] = nil }, key},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			provider, calls := googleCredentialProvider(t, key)
			claims := oidcClaims()
			claims["iss"] = googleIssuer
			tc.change(claims)
			got, err := provider.VerifyGoogleCredential(context.Background(), oauth.GoogleCredential{IDToken: []byte(esToken(t, tc.signer, claims))}, oauth.GoogleCredentialNonce{OriginalNonce: testNonce})
			assertGoogleCredentialFailure(t, got, err, oauth.InvalidProof)
			if calls.Load() != 0 {
				t.Fatal("rejected credential contacted token endpoint")
			}
		})
	}
}

func assertGoogleCredentialFailure(t *testing.T, got oauth.ProviderIdentity, err error, kind oauth.ErrorKind) {
	t.Helper()
	var rejected *oauth.Error
	if !errors.As(err, &rejected) || rejected.Kind() != kind {
		t.Fatalf("wrong credential rejection: %v", err)
	}
	if got.ProviderID() != "" || got.Subject() != "" || got.Issuer() != "" || !got.EvidenceExpiresAt().IsZero() {
		t.Fatal("failed credential yielded identity evidence")
	}
}

func TestGoogleCredentialPreflightAndSecretSafety(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	provider, calls := googleCredentialProvider(t, key)
	claims := oidcClaims()
	claims["iss"] = googleIssuer
	credential := oauth.GoogleCredential{IDToken: []byte(esToken(t, key, claims))}
	nonce := oauth.GoogleCredentialNonce{OriginalNonce: testNonce}
	for name, input := range map[string]oauth.GoogleCredential{"empty": {}, "oversized": {IDToken: bytes.Repeat([]byte{'x'}, provider.Profile().MaxTokenBytes+1)}} {
		t.Run(name, func(t *testing.T) {
			got, err := provider.VerifyGoogleCredential(context.Background(), input, nonce)
			assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
		})
	}
	for _, original := range []string{"", "wrong", testNonce + "="} {
		got, err := provider.VerifyGoogleCredential(context.Background(), credential, oauth.GoogleCredentialNonce{OriginalNonce: original})
		assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := provider.VerifyGoogleCredential(ctx, credential, nonce)
	assertGoogleCredentialFailure(t, got, err, oauth.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation cause lost")
	}
	got, err = provider.VerifyGoogleCredential(nil, credential, nonce)
	assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
	config := providerConfig(t, "https://token.example/token", nil, key)
	config.Issuer = googleIssuer
	strict, err := oauth.NewOIDCProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	defer strict.Close()
	got, err = strict.VerifyGoogleCredential(context.Background(), credential, nonce)
	assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
	provider.Close()
	got, err = provider.VerifyGoogleCredential(context.Background(), credential, nonce)
	assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
	var absent *oauth.OIDCProvider
	got, err = absent.VerifyGoogleCredential(context.Background(), credential, nonce)
	assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
	var zero oauth.OIDCProvider
	got, err = zero.VerifyGoogleCredential(context.Background(), credential, nonce)
	assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
	for _, value := range []any{credential, nonce} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			formatted := fmt.Sprintf(verb, value)
			if strings.Contains(formatted, string(credential.IDToken)) || strings.Contains(formatted, testNonce) {
				t.Fatal("credential or nonce disclosed in diagnostics")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("credential or nonce serialized")
		}
		if _, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); err == nil {
			t.Fatal("credential or nonce serialized as text")
		}
	}
	if calls.Load() != 0 {
		t.Fatal("credential preflight contacted token endpoint")
	}
}

type googleCredentialKeySetFunc func(context.Context, string) ([]byte, error)

func (f googleCredentialKeySetFunc) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	return f(ctx, token)
}

func TestGoogleCredentialCancellationDuringSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keys := &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	config := providerConfig(t, "https://token.example/token", nil, key)
	config.Issuer = googleIssuer
	config.KeySet = googleCredentialKeySetFunc(func(ctx context.Context, token string) ([]byte, error) {
		payload, err := keys.VerifySignature(ctx, token)
		cancel()
		return payload, err
	})
	provider, err := oauth.NewGoogleAccountsProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	claims := oidcClaims()
	claims["iss"] = googleIssuer
	got, err := provider.VerifyGoogleCredential(ctx, oauth.GoogleCredential{IDToken: []byte(esToken(t, key, claims))}, oauth.GoogleCredentialNonce{OriginalNonce: testNonce})
	assertGoogleCredentialFailure(t, got, err, oauth.Unavailable)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("signature-time cancellation cause lost")
	}
}

func TestGoogleCredentialBoundsBeforeSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}
	var signatures atomic.Int32
	config := providerConfig(t, "https://token.example/token", nil, key)
	config.Issuer = googleIssuer
	config.KeySet = googleCredentialKeySetFunc(func(ctx context.Context, token string) ([]byte, error) {
		signatures.Add(1)
		return keys.VerifySignature(ctx, token)
	})
	provider, err := oauth.NewGoogleAccountsProvider(config)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	for _, token := range [][]byte{nil, bytes.Repeat([]byte{'x'}, provider.Profile().MaxTokenBytes+1)} {
		got, err := provider.VerifyGoogleCredential(context.Background(), oauth.GoogleCredential{IDToken: token}, oauth.GoogleCredentialNonce{OriginalNonce: testNonce})
		assertGoogleCredentialFailure(t, got, err, oauth.InvalidInput)
	}
	if signatures.Load() != 0 {
		t.Fatal("empty or oversized credential reached signature verification")
	}
	claims := oidcClaims()
	claims["iss"] = googleIssuer
	wrongOriginal := "AQ" + testNonce[2:]
	got, err := provider.VerifyGoogleCredential(context.Background(), oauth.GoogleCredential{IDToken: []byte(esToken(t, key, claims))}, oauth.GoogleCredentialNonce{OriginalNonce: wrongOriginal})
	assertGoogleCredentialFailure(t, got, err, oauth.InvalidProof)
	if signatures.Load() != 1 {
		t.Fatal("test did not exercise signed original-nonce mismatch")
	}
}
