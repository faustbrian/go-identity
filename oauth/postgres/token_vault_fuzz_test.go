package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/oauth"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// This encrypted parser seed is not a fabricated TokenSet or provider proof.
// Actual provider-origin custody has separate public Exchange-to-vault tests.
func FuzzRPTokenVaultCiphertext(f *testing.F) {
	c := LinkServiceConfig{Schema: "oauth_rp", CurrentEnvelopeKey: "fuzz", EnvelopeKeys: map[string][]byte{"fuzz": bytes.Repeat([]byte{53}, 32)}}
	keys, err := keyring.New(c.EnvelopeKeys)
	if err != nil {
		f.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		f.Fatal(err)
	}
	profile := verifierProfile()
	profile.Scopes = []string{"openid"}
	profile.MaxTokenBytes = 16384
	s := &LinkService{envelopes: crypto, profiles: map[string]oauth.ProviderProfile{profile.ID: profile}, config: func() LinkServiceConfig { return c }}
	prepared := rpPreparedTokenSet{Schema: 1, Binding: rpTokenVaultBinding{TenantID: "tenant-a", UserID: "user-a", AccountID: "account-a", ProviderID: profile.ID, Issuer: profile.Issuer, ClientID: profile.ClientID, ConfigurationVersion: profile.Version, AccountVersion: 1, SocialLinkVersion: 2}, RequestedScopes: []string{"openid"}, GrantedScopes: []string{"openid"}, ReceivedAt: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC), AccessExpiresAt: time.Date(2026, 11, 2, 0, 1, 0, 0, time.UTC), Version: 1, SocialConnectionVersion: 1}
	aad, err := rpTokenVaultAAD(prepared)
	if err != nil {
		f.Fatal(err)
	}
	frame := []byte("OITV1\x00\x00\x00\x01a\x00\x00\x00\x00\x00\x00\x00\x01i")
	defer clear(frame)
	wire, err := s.sealRP(context.Background(), aad, frame)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(wire)
	f.Add([]byte{})
	f.Add([]byte("SEV1"))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > rpMaximumTokenCiphertext {
			return
		}
		candidate := prepared
		candidate.Ciphertext = input
		err := s.validatePreparedProviderTokens(context.Background(), candidate)
		if err == nil {
			// Fuzz workers each create a fresh randomized envelope, so accepted
			// ciphertext identity is not the oracle. Authentic plaintext is.
			plain, err := s.openRP(context.Background(), aad, input, rpMaximumTokenCiphertext)
			defer clear(plain)
			if err != nil || !bytes.Equal(plain, frame) {
				t.Fatal("ciphertext restored different token bytes")
			}
		}
	})
}
