package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

func TestProxyOIDCEvidenceAuthenticatesSelectedProviderAuthorityEpoch(t *testing.T) {
	codec, _, _, binding, original := proxyOIDCEvidenceFixture(t)
	binding.ProviderAuthorityEpoch = 41
	wire, err := codec.Seal(t.Context(), binding, original)
	if err != nil {
		t.Fatal("a live epoch independent of the exchange profile version could not seal evidence", err)
	}
	restored, err := codec.Open(t.Context(), binding, wire)
	if err != nil || restored.ProviderID() != original.ProviderID() || restored.Subject() != original.Subject() {
		t.Fatal("the matching selected live epoch could not recover provider evidence", err)
	}
	for _, epoch := range []uint64{0, 42} {
		changed := binding
		changed.ProviderAuthorityEpoch = epoch
		if got, err := codec.Open(t.Context(), changed, wire); err == nil || got != (ProviderIdentity{}) {
			t.Fatal("another live epoch or the legacy selection recovered provider evidence")
		}
	}

	changedProfile := binding
	changedProfile.ProviderVersion++
	if got, err := codec.Open(t.Context(), changedProfile, wire); err == nil || got != (ProviderIdentity{}) {
		t.Fatal("matching live epoch stopped authenticating the independent provider profile version")
	}
	if got, err := codec.Seal(t.Context(), changedProfile, original); err == nil || len(got) != 0 {
		t.Fatal("matching live epoch accepted evidence from a different exchange profile version")
	}
	profileContext, err := binding.context("proxy-v1")
	if err != nil || profileContext.Values()["purpose"] != "identity.oauth.proxy-oidc-evidence.v2" {
		t.Fatal("selected live epoch did not select the v2 evidence purpose", err)
	}
}

func TestProxyOIDCEvidenceZeroEpochPreservesLegacyFrame(t *testing.T) {
	codec, _, crypto, binding, original := proxyOIDCEvidenceFixture(t)
	legacyContext := frozenProxyOIDCLegacyContext(t, binding, "proxy-v1")
	profile := proxyOIDCProfile{
		Subject: original.subject, IssuedAt: original.idTokenIssuedAt.UTC(), ExpiresAt: original.idTokenExpiresAt.UTC(),
		AuthenticationTime: original.authenticatedAt.UTC(), EvidenceExpiresAt: original.EvidenceExpiresAt().UTC(),
		HasAuthenticationTime: original.hasAuthenticationTime,
	}
	plain, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	envelope, err := crypto.Encrypt(t.Context(), secretenvelope.EncryptRequest{
		Plaintext: plain, KeyReference: "proxy-v1", Context: legacyContext,
	})
	if err != nil {
		t.Fatal(err)
	}
	legacyWire, err := envelope.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	restored, err := codec.Open(t.Context(), binding, legacyWire)
	if err != nil || restored.Subject() != original.Subject() {
		t.Fatal("zero epoch could not open the frozen legacy frame", err)
	}
	selected := binding
	selected.ProviderAuthorityEpoch = 41
	if got, err := codec.Open(t.Context(), selected, legacyWire); err == nil || got != (ProviderIdentity{}) {
		t.Fatal("a live epoch recovered evidence sealed under the legacy frame")
	}

	wire, err := codec.Seal(t.Context(), binding, original)
	if err != nil {
		t.Fatal(err)
	}
	written, err := secretenvelope.ParseEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := crypto.Decrypt(t.Context(), secretenvelope.DecryptRequest{Envelope: written, Context: legacyContext})
	defer clear(opened)
	if err != nil {
		t.Fatal("zero epoch no longer writes the exact legacy authenticated frame", err)
	}
}

// This is the pre-epoch v1 frame from 9ed8ac37, independent of the codec's
// context builder so a changed zero-epoch frame cannot validate itself.
func frozenProxyOIDCLegacyContext(t *testing.T, b ProxyOIDCEvidenceBinding, key string) secretenvelope.Context {
	t.Helper()
	remember, err := b.Remember.Bindings()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := json.Marshal([]any{"identity.oauth.proxy-oidc-evidence.v1", "verified-oidc", b.TenantID, b.CommandID, b.TransactionID,
		b.RequestFingerprint, b.StateDigest, b.PKCEChallengeDigest, b.ProductionDeployment, b.PreviewDeployment,
		b.ProviderID, b.ProviderVersion, b.Issuer, b.ClientID, b.PreviewOrigin, b.PreviewRedirect, b.Recipient,
		b.ClaimsProfile, b.ClaimsVersion, remember, b.IssuedAt.UTC(), b.ExpiresAt.UTC(), key})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(frame)
	digest := sha256.Sum256(frame)
	legacy, err := secretenvelope.NewContext(map[string]string{
		"purpose": "identity.oauth.proxy-oidc-evidence.v1", "binding": base64.RawURLEncoding.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	return legacy
}
