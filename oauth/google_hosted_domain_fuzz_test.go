package oauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/oauth"
)

func FuzzGoogleHostedDomainSignedClaim(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	constraint, err := oauth.NewGoogleHostedDomain("example.com")
	if err != nil {
		f.Fatal(err)
	}
	for _, value := range []string{"example.com", "", "EXAMPLE.COM", "example.com.", "other.example.com", "example.com\x00", "example.com\n", "exаmple.com", strings.Repeat("x", 16385)} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		provider, _ := googleHostedDomainProvider(t, key)
		claims := oidcClaims()
		claims["iss"], claims["hd"] = googleIssuer, value
		got, err := provider.VerifyGoogleCredentialForHostedDomain(context.Background(), oauth.GoogleCredential{IDToken: []byte(esToken(t, key, claims))}, oauth.GoogleCredentialNonce{OriginalNonce: testNonce}, constraint)
		if value == "example.com" {
			if err != nil || got.Subject() != claims["sub"] || got.Issuer() != googleIssuer {
				t.Fatal("exact signed hosted domain denied", err)
			}
			return
		}
		var rejected *oauth.Error
		if !errors.As(err, &rejected) || rejected.Kind() != oauth.InvalidProof && rejected.Kind() != oauth.InvalidInput || got != (oauth.ProviderIdentity{}) {
			t.Fatal("nonmatching signed hosted domain produced provider evidence")
		}
	})
}
