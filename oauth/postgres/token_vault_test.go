package postgres

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type rpVaultClock struct{ now time.Time }

func (c rpVaultClock) Now() time.Time { return c.now }

// Tokens come only from the actual core exchange/validator, not fabricated
// private TokenSet state or a vault-owned provider protocol implementation.
func rpVaultTokens(t *testing.T, reported bool, requested ...[]string) (oauth.TokenSet, oauth.ProviderProfile) {
	t.Helper()
	now := time.Date(2026, 11, 2, 0, 0, 0, 123456789, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	claims, err := json.Marshal(map[string]any{"iss": "https://issuer.example", "sub": "provider-subject", "aud": "client", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "nonce": nonce})
	if err != nil {
		t.Fatal(err)
	}
	message := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(message))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	idToken := message + "." + base64.RawURLEncoding.EncodeToString(signature)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		response := map[string]any{"access_token": "synthetic-vault-access", "refresh_token": "synthetic-vault-refresh", "id_token": idToken, "token_type": "Bearer", "expires_in": 3600}
		if reported {
			response["scope"] = "openid"
		}
		if json.NewEncoder(w).Encode(response) != nil {
			t.Error("token fixture response failed")
		}
	}))
	t.Cleanup(server.Close)
	scopes := []string{"openid", "profile"}
	if len(requested) > 0 {
		scopes = requested[0]
	}
	provider, err := oauth.NewOIDCProvider(oauth.OIDCConfig{ID: "generic", Version: 7, Issuer: "https://issuer.example", AuthorizationEndpoint: "https://issuer.example/authorize", TokenEndpoint: server.URL + "/token", RedirectURI: "https://app.example/callback", ClientID: "client", ClientAuthentication: oauth.PublicClient, Scopes: scopes, Algorithms: []string{"ES256"}, KeySet: &coreoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, HTTPClient: server.Client(), Clock: rpVaultClock{now}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	callback, err := identity.NewOAuthCallbackInput([]byte("synthetic-vault-code"), nonce, identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	defer callback.Destroy()
	pkce, err := oauth.NewPKCEVerifier(bytes.Repeat([]byte{'v'}, 43))
	if err != nil {
		t.Fatal(err)
	}
	defer pkce.Destroy()
	exchanged, err := provider.Exchange(context.Background(), callback, pkce, nonce)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(exchanged.Tokens.Destroy)
	return exchanged.Tokens, provider.Profile()
}

func rpVaultFixture(t *testing.T, reported bool) (*LinkService, rpTokenVaultBinding, oauth.TokenSet) {
	t.Helper()
	tokens, profile := rpVaultTokens(t, reported)
	c := LinkServiceConfig{Schema: "oauth_rp", CurrentEnvelopeKey: "vault-v1", EnvelopeKeys: map[string][]byte{"vault-v1": bytes.Repeat([]byte{41}, 32)}}
	keys, err := keyring.New(c.EnvelopeKeys)
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	s := &LinkService{envelopes: crypto, profiles: map[string]oauth.ProviderProfile{profile.ID: profile}, config: func() LinkServiceConfig { return c }}
	b := rpTokenVaultBinding{TenantID: "tenant-a", UserID: "user-a", AccountID: "account-a", ProviderID: profile.ID, Issuer: profile.Issuer, ClientID: profile.ClientID, ConfigurationVersion: profile.Version, AccountVersion: 1, SocialLinkVersion: 2}
	return s, b, tokens
}

func TestRPTokenVaultConsumesActualTokensAndPreservesExactMetadata(t *testing.T) {
	for _, reported := range []bool{false, true} {
		t.Run(fmt.Sprint(reported), func(t *testing.T) {
			s, b, tokens := rpVaultFixture(t, reported)
			wantRequested, wantGranted := tokens.RequestedScopes(), tokens.GrantedScopes()
			received, expires := tokens.ReceivedAt(), tokens.ExpiresAt()
			var original [3][32]byte
			if err := tokens.Use(context.Background(), func(_ context.Context, b oauth.TokenBytes) error {
				original = [3][32]byte{sha256.Sum256(b.AccessToken), sha256.Sum256(b.RefreshToken), sha256.Sum256(b.IDToken)}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			prepared, err := s.sealProviderTokens(context.Background(), b, tokens)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(prepared.RequestedScopes, wantRequested) || !reflect.DeepEqual(prepared.GrantedScopes, wantGranted) || prepared.ScopeReported != reported || prepared.ReceivedAt != received || prepared.AccessExpiresAt != expires || prepared.Version != 1 || prepared.SocialConnectionVersion != 1 || prepared.Binding != b {
				t.Fatal("original token metadata changed")
			}
			if tokens.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
				t.Fatal("original token custody survived encryption")
			}
			if _, err := envelope.ParseEnvelope(prepared.Ciphertext); err != nil {
				t.Fatal("vault does not use actual envelope format")
			}
			if err := s.validatePreparedProviderTokens(context.Background(), prepared); err != nil {
				t.Fatal(err)
			}
			aad, err := rpTokenVaultAAD(prepared)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := s.openRP(context.Background(), aad, prepared.Ciphertext, rpMaximumTokenCiphertext)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			remaining := plain[len(rpTokenVaultHeader):]
			for _, sum := range original {
				size := int(binary.BigEndian.Uint32(remaining))
				remaining = remaining[4:]
				if sha256.Sum256(remaining[:size]) != sum {
					t.Fatal("encrypted token bytes changed")
				}
				remaining = remaining[size:]
			}
			if len(remaining) != 0 {
				t.Fatal("vault added unowned token data")
			}
			wire, err := json.Marshal(prepared)
			if err != nil {
				t.Fatal("trusted encrypted output cannot retain prepared token custody", err)
			}
			for _, secret := range []string{"synthetic-vault-access", "synthetic-vault-refresh"} {
				if bytes.Contains(wire, []byte(secret)) || strings.Contains(fmt.Sprintf("%#v", prepared), secret) {
					t.Fatal("token entered metadata/diagnostics")
				}
			}
			var restored rpPreparedTokenSet
			if json.Unmarshal(wire, &restored) != nil || s.validatePreparedProviderTokens(context.Background(), restored) != nil {
				t.Fatal("prepared token output failed native restoration")
			}
		})
	}
}

func TestRPTokenVaultAuthenticatesThenRejectsMalformedTokenFrames(t *testing.T) {
	s, b, tokens := rpVaultFixture(t, true)
	prepared, err := s.sealProviderTokens(context.Background(), b, tokens)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := rpTokenVaultAAD(prepared)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := s.openRP(context.Background(), aad, prepared.Ciphertext, rpMaximumTokenCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated header":   func(v []byte) []byte { return v[:3] },
		"wrong header":       func(v []byte) []byte { v[0] ^= 1; return v },
		"empty access token": func(v []byte) []byte { binary.BigEndian.PutUint32(v[len(rpTokenVaultHeader):], 0); return v },
		"oversize token":     func(v []byte) []byte { binary.BigEndian.PutUint32(v[len(rpTokenVaultHeader):], 16385); return v },
		"partial token":      func(v []byte) []byte { return v[:len(v)-1] },
		"trailing bytes":     func(v []byte) []byte { return append(v, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			raw := mutate(bytes.Clone(plain))
			defer clear(raw)
			changed := prepared
			changed.Ciphertext, err = s.sealRP(context.Background(), aad, raw)
			if err != nil {
				t.Fatal(err)
			}
			if s.validatePreparedProviderTokens(context.Background(), changed) == nil {
				t.Fatal("malformed authenticated bearer frame restored")
			}
		})
	}
}

func TestRPTokenVaultAuthenticatesEveryOwnershipAndMetadataDimension(t *testing.T) {
	s, b, tokens := rpVaultFixture(t, true)
	prepared, err := s.sealProviderTokens(context.Background(), b, tokens)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*rpPreparedTokenSet){
		"tenant":              func(p *rpPreparedTokenSet) { p.Binding.TenantID = "tenant-b" },
		"user":                func(p *rpPreparedTokenSet) { p.Binding.UserID = "user-b" },
		"account":             func(p *rpPreparedTokenSet) { p.Binding.AccountID = "account-b" },
		"provider":            func(p *rpPreparedTokenSet) { p.Binding.ProviderID = "other" },
		"issuer":              func(p *rpPreparedTokenSet) { p.Binding.Issuer = "https://other.example" },
		"client":              func(p *rpPreparedTokenSet) { p.Binding.ClientID = "other" },
		"configuration":       func(p *rpPreparedTokenSet) { p.Binding.ConfigurationVersion++ },
		"account version":     func(p *rpPreparedTokenSet) { p.Binding.AccountVersion++ },
		"social link version": func(p *rpPreparedTokenSet) { p.Binding.SocialLinkVersion++ },
		"vault version":       func(p *rpPreparedTokenSet) { p.Version++ },
		"connection version":  func(p *rpPreparedTokenSet) { p.SocialConnectionVersion++ },
		"requested scope":     func(p *rpPreparedTokenSet) { p.RequestedScopes = []string{"openid"} },
		"granted scope":       func(p *rpPreparedTokenSet) { p.GrantedScopes = []string{"openid", "profile"} },
		"scope reported":      func(p *rpPreparedTokenSet) { p.ScopeReported = false },
		"received at":         func(p *rpPreparedTokenSet) { p.ReceivedAt = p.ReceivedAt.Add(time.Nanosecond) },
		"access expiry":       func(p *rpPreparedTokenSet) { p.AccessExpiresAt = p.AccessExpiresAt.Add(time.Second) },
		"ciphertext": func(p *rpPreparedTokenSet) {
			p.Ciphertext = bytes.Clone(p.Ciphertext)
			p.Ciphertext[len(p.Ciphertext)-1] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := prepared
			mutate(&changed)
			if s.validatePreparedProviderTokens(context.Background(), changed) == nil {
				t.Fatal("changed vault input authenticated")
			}
		})
	}
	if err := s.persistProviderTokens(context.Background(), kernel.AccountLinkWork{}, nil, prepared); err == nil {
		t.Fatal("fabricated Work persisted provider tokens")
	}
}

func TestRPTokenVaultCancellationBoundsAndRetainedRotation(t *testing.T) {
	s, b, tokens := rpVaultFixture(t, true)
	prepared, err := s.sealProviderTokens(context.Background(), b, tokens)
	if err != nil {
		t.Fatal(err)
	}
	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if !errors.Is(s.validatePreparedProviderTokens(cancelled, prepared), context.Canceled) {
		t.Fatal("validation lost cancellation")
	}
	_, _, cancelledTokens := rpVaultFixture(t, true)
	if _, err := s.sealProviderTokens(cancelled, b, cancelledTokens); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled encryption lost cancellation")
	}
	if cancelledTokens.Use(context.Background(), func(context.Context, oauth.TokenBytes) error { return nil }) == nil {
		t.Fatal("cancelled encryption retained original token custody")
	}
	if err := s.validatePreparedProviderTokens(nil, prepared); err == nil {
		t.Fatal("nil validation context admitted")
	}
	if _, err := s.sealProviderTokens(context.Background(), b, oauth.TokenSet{}); err == nil {
		t.Fatal("zero token custody admitted")
	}
	for _, wire := range [][]byte{nil, bytes.Repeat([]byte{1}, 65537)} {
		changed := prepared
		changed.Ciphertext = wire
		if s.validatePreparedProviderTokens(context.Background(), changed) == nil {
			t.Fatal("unbounded ciphertext admitted")
		}
	}
	c := s.config()
	c.CurrentEnvelopeKey = "vault-v2"
	c.EnvelopeKeys = map[string][]byte{"vault-v1": bytes.Repeat([]byte{41}, 32), "vault-v2": bytes.Repeat([]byte{42}, 32)}
	rotated := *s
	rotated.config = func() LinkServiceConfig { return c }
	keys, err := keyring.New(c.EnvelopeKeys)
	if err != nil {
		t.Fatal(err)
	}
	rotated.envelopes, err = envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotated.validatePreparedProviderTokens(context.Background(), prepared); err != nil {
		t.Fatal("retained encryption key could not restore original tokens", err)
	}
	newTokens, _ := rpVaultTokens(t, true)
	newPrepared, err := rotated.sealProviderTokens(context.Background(), b, newTokens)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := envelope.ParseEnvelope(newPrepared.Ciphertext)
	if err != nil || sealed.KeyReference() != "vault-v2" {
		t.Fatal("new encryption ignored selected rotated key")
	}
	if s.validatePreparedProviderTokens(context.Background(), newPrepared) == nil {
		t.Fatal("unretained new wrapping key silently accepted")
	}
	delete(c.EnvelopeKeys, "vault-v1")
	keys, err = keyring.New(c.EnvelopeKeys)
	if err != nil {
		t.Fatal(err)
	}
	rotated.envelopes, err = envelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotated.validatePreparedProviderTokens(context.Background(), prepared); err == nil {
		t.Fatal("missing original wrapping key silently replaced custody")
	}
}
