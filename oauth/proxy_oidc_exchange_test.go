package oauth_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauth "github.com/faustbrian/go-identity/oauth"
	"github.com/faustbrian/go-identity/session"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

func TestProxyOIDCEvidencePublicExchangeBindsExactClientAndProviderVersion(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claims := oidcClaims()
	claims["name"] = "private-production-display-name"
	claims["email_verified"] = true
	signedToken := esToken(t, key, claims)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "private-production-access-token", "refresh_token": "private-production-refresh-token",
			"id_token": signedToken, "token_type": "Bearer", "expires_in": 3600,
		})
	}))
	t.Cleanup(server.Close)
	config := providerConfig(t, server.URL+"/token", server.Client(), key)
	provider, err := oauth.NewOIDCProviderWithClaims(config, oauth.OIDCClaimProjectionConfig{Names: []string{"name", "email_verified", "absent"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(provider.Close)
	result, err := provider.Exchange(context.Background(), callback(t), verifier(t), testNonce)
	if err != nil {
		t.Fatal("production code exchange did not produce verified identity", err)
	}
	result.Tokens.Destroy()
	keys, err := keyring.New(map[string][]byte{"proxy-v1": bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := secretenvelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	codec, err := oauth.NewProxyOIDCEvidenceCodec(crypto, fixedClock{testNow}, "proxy-v1", nil)
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: 8 * time.Hour,
		IdleTTL: time.Hour, RefreshAfter: 10 * time.Minute, FreshFor: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := oauth.ProxyOIDCEvidenceBinding{
		TenantID: "tenant-a", CommandID: identity.CommandID("AQEBAQEBAQEBAQEBAQEBAQ"),
		TransactionID:      identity.PreAuthTransactionID("AgICAgICAgICAgICAgICAg"),
		RequestFingerprint: sha256.Sum256([]byte("original-request")),
		StateDigest:        sha256.Sum256([]byte(testNonce)), PKCEChallengeDigest: sha256.Sum256([]byte(verifier(t).Challenge())),
		ProductionDeployment: "production-a", PreviewDeployment: "preview-a",
		ProviderID: config.ID, ProviderVersion: config.Version, Issuer: config.Issuer, ClientID: config.ClientID,
		PreviewOrigin: "https://preview.example", PreviewRedirect: "https://preview.example/oauth/callback",
		Recipient: "preview-identity", ClaimsProfile: "preview-profile", ClaimsVersion: 3,
		Remember: remember, IssuedAt: testNow, ExpiresAt: testNow.Add(30 * time.Second),
	}
	wire, err := codec.Seal(context.Background(), binding, result.Identity)
	if err != nil || len(wire) == 0 {
		t.Fatal("real OIDC exchange could not be handed to its exact preview recipient", err)
	}
	for _, secret := range []string{signedToken, "private-production-access-token", "private-production-refresh-token", "private-production-display-name", "provider-subject"} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Fatal("handoff disclosed token custody or selected source profile data")
		}
	}
	restored, err := codec.Open(context.Background(), binding, wire)
	if err != nil || restored.Subject() != result.Identity.Subject() || !restored.IDTokenExpiresAt().Equal(testNow.Add(time.Minute)) {
		t.Fatal("public handoff changed verified identity or original signed expiry", err)
	}
	if when, present := restored.AuthenticationTime(); present || !when.IsZero() {
		t.Fatal("public handoff invented authentication time from signed iat")
	}
	if len((oauth.ExchangeResult{Identity: restored}).VerifiedOIDCClaims()) != 0 {
		t.Fatal("public linked-account handoff transferred production-only selected claims")
	}
	for _, tc := range []struct {
		name   string
		change func(*oauth.ProxyOIDCEvidenceBinding)
	}{
		{"other-client", func(b *oauth.ProxyOIDCEvidenceBinding) { b.ClientID = "other-client" }},
		{"other-provider-version", func(b *oauth.ProxyOIDCEvidenceBinding) { b.ProviderVersion++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := binding
			tc.change(&changed)
			if wire, err := codec.Seal(context.Background(), changed, result.Identity); err == nil || len(wire) != 0 {
				t.Fatal("real exchange was relabeled with a different client or provider version")
			}
		})
	}
}
