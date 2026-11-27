package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

type proxyOIDCEvidenceClock struct{ now time.Time }

func (c *proxyOIDCEvidenceClock) Now() time.Time { return c.now }

func proxyOIDCEvidenceFixture(t testing.TB) (*ProxyOIDCEvidenceCodec, *proxyOIDCEvidenceClock, *secretenvelope.Service, ProxyOIDCEvidenceBinding, ProviderIdentity) {
	t.Helper()
	keys, err := keyring.New(map[string][]byte{
		"proxy-v1": bytes.Repeat([]byte{1}, 32),
		"proxy-v2": bytes.Repeat([]byte{2}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	crypto, err := secretenvelope.NewService(keys)
	if err != nil {
		t.Fatal(err)
	}
	clock := &proxyOIDCEvidenceClock{now: time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)}
	codec, err := NewProxyOIDCEvidenceCodec(crypto, clock, "proxy-v1", nil)
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
	binding := ProxyOIDCEvidenceBinding{
		TenantID: "tenant-a", CommandID: identity.CommandID("AQEBAQEBAQEBAQEBAQEBAQ"),
		TransactionID:      identity.PreAuthTransactionID("AgICAgICAgICAgICAgICAg"),
		RequestFingerprint: sha256.Sum256([]byte("original-request")),
		StateDigest:        sha256.Sum256([]byte("original-state")), PKCEChallengeDigest: sha256.Sum256([]byte("original-pkce-challenge")),
		ProductionDeployment: "production-a", PreviewDeployment: "preview-a",
		ProviderID: "production-oidc", ProviderVersion: 7,
		Issuer: "https://issuer.example", ClientID: "production-client",
		PreviewOrigin: "https://preview.example", PreviewRedirect: "https://preview.example/oauth/callback",
		Recipient: "preview-identity", ClaimsProfile: "preview-profile", ClaimsVersion: 3,
		Remember: remember, IssuedAt: clock.now.Add(-time.Second), ExpiresAt: clock.now.Add(2 * time.Minute),
	}
	// Only the already-verified exchange owner can construct these fields in
	// production; this package-local fixture does not add a claim constructor.
	profile := ProviderIdentity{
		provider: binding.ProviderID, issuer: binding.Issuer, subject: "private-provider-subject",
		authenticatedAt: clock.now.Add(-3 * time.Minute), hasAuthenticationTime: true,
		idTokenIssuedAt: clock.now.Add(-time.Minute), idTokenExpiresAt: clock.now.Add(3 * time.Minute),
		exchangeClientID: binding.ClientID, exchangeProviderVersion: binding.ProviderVersion,
		oidcClaims: &oidcClaimProjection{claims: []VerifiedOIDCClaim{
			{name: "name", kind: OIDCClaimString, text: "private-display-name"},
			{name: "email", kind: OIDCClaimString, text: "private-mailbox@example.invalid"},
			{name: "email_verified", kind: OIDCClaimBool, flag: false},
			{name: "nickname", kind: OIDCClaimString, text: ""},
			{name: "locale", kind: OIDCClaimNull},
			{name: "department", kind: OIDCClaimAbsent},
		}},
	}
	return codec, clock, crypto, binding, profile
}

func FuzzProxyOIDCEvidenceOpen(f *testing.F) {
	codec, _, _, binding, original := proxyOIDCEvidenceFixture(f)
	wire, err := codec.Seal(context.Background(), binding, original)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add(wire)
	f.Add(wire[:len(wire)-1])
	f.Fuzz(func(t *testing.T, input []byte) {
		profile, err := codec.Open(t.Context(), binding, input)
		if err != nil {
			if profile != (ProviderIdentity{}) {
				t.Fatal("refused evidence disclosed original profile")
			}
			return
		}
		if profile.ProviderID() != original.ProviderID() || profile.Issuer() != original.Issuer() || profile.Subject() != original.Subject() || !profile.EvidenceExpiresAt().Equal(original.EvidenceExpiresAt()) || profile.exchangeClientID != "" || profile.exchangeProviderVersion != 0 {
			t.Fatal("accepted evidence changed the configured provider observation")
		}
	})
}

func TestProxyOIDCEvidenceOpaqueProfileRoundTripPreservesSignedLifetime(t *testing.T) {
	codec, _, _, binding, original := proxyOIDCEvidenceFixture(t)
	wire, err := codec.Seal(context.Background(), binding, original)
	if err != nil || len(wire) == 0 {
		t.Fatal("valid production exchange evidence was not sealed", err)
	}
	for _, private := range []string{original.Subject(), "private-display-name", "private-mailbox@example.invalid"} {
		if bytes.Contains(wire, []byte(private)) {
			t.Fatal("sealed evidence disclosed a source profile value")
		}
	}
	again, err := codec.Seal(context.Background(), binding, original)
	if err != nil || bytes.Equal(wire, again) {
		t.Fatal("independent seals did not produce randomized envelopes", err)
	}
	restored, err := codec.Open(context.Background(), binding, wire)
	if err != nil {
		t.Fatal("exact recipient could not open production evidence", err)
	}
	if restored.ProviderID() != original.ProviderID() || restored.Issuer() != original.Issuer() || restored.Subject() != original.Subject() {
		t.Fatal("provider identity changed during handoff")
	}
	gotAuthentication, gotPresent := restored.AuthenticationTime()
	wantAuthentication, wantPresent := original.AuthenticationTime()
	if gotPresent != wantPresent || !gotAuthentication.Equal(wantAuthentication) {
		t.Fatal("handoff changed authentication-time presence or value")
	}
	if !restored.IDTokenIssuedAt().Equal(original.IDTokenIssuedAt()) || !restored.IDTokenExpiresAt().Equal(original.IDTokenExpiresAt()) || !restored.EvidenceExpiresAt().Equal(original.EvidenceExpiresAt()) {
		t.Fatal("handoff replaced the original signed lifetime with its envelope lifetime")
	}
	if len((ExchangeResult{Identity: restored}).VerifiedOIDCClaims()) != 0 {
		t.Fatal("linked-account handoff transferred production-only selected claims")
	}
	if resealed, err := codec.Seal(context.Background(), binding, restored); err == nil || len(resealed) != 0 {
		t.Fatal("a preview observation was promoted to fresh production exchange evidence")
	}
}

func TestProxyOIDCEvidenceAuthenticatesEveryOriginalBinding(t *testing.T) {
	codec, _, _, binding, original := proxyOIDCEvidenceFixture(t)
	wire, err := codec.Seal(context.Background(), binding, original)
	if err != nil {
		t.Fatal(err)
	}
	persistent, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.PersistentSession, AbsoluteTTL: 8 * time.Hour,
		IdleTTL: time.Hour, RefreshAfter: 10 * time.Minute, FreshFor: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	otherBrowser, err := session.NewRememberPolicy(session.RememberPolicySpec{
		Choice: session.BrowserSession, AbsoluteTTL: 7 * time.Hour,
		IdleTTL: time.Hour, RefreshAfter: 10 * time.Minute, FreshFor: 30 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*ProxyOIDCEvidenceBinding)
	}{
		{"tenant", func(b *ProxyOIDCEvidenceBinding) { b.TenantID = "tenant-b" }},
		{"command", func(b *ProxyOIDCEvidenceBinding) { b.CommandID = "AwMDAwMDAwMDAwMDAwMDAw" }},
		{"transaction", func(b *ProxyOIDCEvidenceBinding) { b.TransactionID = "BAQEBAQEBAQEBAQEBAQEBA" }},
		{"request-fingerprint", func(b *ProxyOIDCEvidenceBinding) { b.RequestFingerprint[0] ^= 1 }},
		{"state-digest", func(b *ProxyOIDCEvidenceBinding) { b.StateDigest[0] ^= 1 }},
		{"pkce-challenge-digest", func(b *ProxyOIDCEvidenceBinding) { b.PKCEChallengeDigest[0] ^= 1 }},
		{"production-deployment", func(b *ProxyOIDCEvidenceBinding) { b.ProductionDeployment = "production-b" }},
		{"preview-deployment", func(b *ProxyOIDCEvidenceBinding) { b.PreviewDeployment = "preview-b" }},
		{"provider", func(b *ProxyOIDCEvidenceBinding) { b.ProviderID = "other-provider" }},
		{"provider-version", func(b *ProxyOIDCEvidenceBinding) { b.ProviderVersion++ }},
		{"issuer", func(b *ProxyOIDCEvidenceBinding) { b.Issuer = "https://other-issuer.example" }},
		{"client", func(b *ProxyOIDCEvidenceBinding) { b.ClientID = "other-client" }},
		{"preview-origin", func(b *ProxyOIDCEvidenceBinding) {
			b.PreviewOrigin = "https://other-preview.example"
			b.PreviewRedirect = "https://other-preview.example/oauth/callback"
		}},
		{"preview-redirect", func(b *ProxyOIDCEvidenceBinding) { b.PreviewRedirect = "https://preview.example/other/callback" }},
		{"recipient", func(b *ProxyOIDCEvidenceBinding) { b.Recipient = "other-recipient" }},
		{"claims-profile", func(b *ProxyOIDCEvidenceBinding) { b.ClaimsProfile = "other-profile" }},
		{"claims-version", func(b *ProxyOIDCEvidenceBinding) { b.ClaimsVersion++ }},
		{"remember-choice", func(b *ProxyOIDCEvidenceBinding) { b.Remember = persistent }},
		{"remember-lifetime", func(b *ProxyOIDCEvidenceBinding) { b.Remember = otherBrowser }},
		{"issued-at", func(b *ProxyOIDCEvidenceBinding) { b.IssuedAt = b.IssuedAt.Add(-time.Second) }},
		{"expires-at", func(b *ProxyOIDCEvidenceBinding) { b.ExpiresAt = b.ExpiresAt.Add(-time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := binding
			tc.change(&changed)
			got, err := codec.Open(context.Background(), changed, wire)
			if err == nil || got != (ProviderIdentity{}) {
				t.Fatal("changed original binding disclosed provider identity")
			}
		})
	}
}

func TestProxyOIDCEvidenceRefusesTamperedAndMalformedEnvelopes(t *testing.T) {
	codec, _, _, binding, original := proxyOIDCEvidenceFixture(t)
	wire, err := codec.Seal(context.Background(), binding, original)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Clone(wire)
	tampered[len(tampered)-1] ^= 1
	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"empty", nil}, {"plaintext-profile", []byte(`{"subject":"private-provider-subject"}`)},
		{"truncated", wire[:len(wire)-1]}, {"trailing-data", append(bytes.Clone(wire), 0)}, {"tampered", tampered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := codec.Open(context.Background(), binding, tc.wire)
			if err == nil || got != (ProviderIdentity{}) {
				t.Fatal("unauthenticated envelope disclosed provider identity")
			}
		})
	}
}

func TestProxyOIDCEvidenceSealRequiresOriginalOIDCExchangeProvenance(t *testing.T) {
	codec, clock, _, binding, original := proxyOIDCEvidenceFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*ProviderIdentity)
	}{
		{"zero-identity", func(i *ProviderIdentity) { *i = ProviderIdentity{} }},
		{"missing-exchange-client", func(i *ProviderIdentity) { i.exchangeClientID = "" }},
		{"other-exchange-client", func(i *ProviderIdentity) { i.exchangeClientID = "other-client" }},
		{"missing-exchange-version", func(i *ProviderIdentity) { i.exchangeProviderVersion = 0 }},
		{"other-exchange-version", func(i *ProviderIdentity) { i.exchangeProviderVersion++ }},
		{"other-provider", func(i *ProviderIdentity) { i.provider = "other-provider" }},
		{"other-issuer", func(i *ProviderIdentity) { i.issuer = "https://other-issuer.example" }},
		{"missing-signed-iat", func(i *ProviderIdentity) { i.idTokenIssuedAt = time.Time{} }},
		{"missing-signed-exp", func(i *ProviderIdentity) { i.idTokenExpiresAt = time.Time{} }},
		{"expired-signed-exp", func(i *ProviderIdentity) { i.idTokenExpiresAt = clock.now }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := original
			tc.change(&changed)
			wire, err := codec.Seal(context.Background(), binding, changed)
			if err == nil || len(wire) != 0 {
				t.Fatal("profile without matching live production exchange proof was sealed")
			}
		})
	}
}

func TestProxyOIDCEvidenceExpiresAtOriginalHandoffBoundary(t *testing.T) {
	codec, clock, _, binding, original := proxyOIDCEvidenceFixture(t)
	wire, err := codec.Seal(context.Background(), binding, original)
	if err != nil {
		t.Fatal(err)
	}
	// Leave enough real execution budget to unwrap. The exact boundary below
	// must still deny; the fake policy clock cannot make key I/O instantaneous.
	clock.now = binding.ExpiresAt.Add(-time.Second)
	if _, err := codec.Open(context.Background(), binding, wire); err != nil {
		t.Fatal("handoff expired before its exact boundary", err)
	}
	clock.now = binding.ExpiresAt
	if got, err := codec.Open(context.Background(), binding, wire); err == nil || got != (ProviderIdentity{}) {
		t.Fatal("handoff remained usable at expiry")
	}
	if renewed, err := codec.Seal(context.Background(), binding, original); err == nil || len(renewed) != 0 {
		t.Fatal("expired handoff was sealed again")
	}
}

func TestProxyOIDCEvidenceRejectsNoncanonicalPreviewTargets(t *testing.T) {
	codec, _, _, binding, original := proxyOIDCEvidenceFixture(t)
	for _, tc := range []struct{ origin, redirect string }{
		{"https://preview.example", "https://other.example/oauth/callback"},
		{"https://preview.example", "https://preview.example/oauth/../callback"},
		{"https://preview.example", "https://preview.example/oauth/%63allback"},
		{"https://preview.example:443", "https://preview.example:443/oauth/callback"},
		{"https://0177.0.0.1", "https://0177.0.0.1/oauth/callback"},
		{"https://xn--example-9za.example", "https://xn--example-9za.example/oauth/callback"},
	} {
		bad := binding
		bad.PreviewOrigin, bad.PreviewRedirect = tc.origin, tc.redirect
		if wire, err := codec.Seal(context.Background(), bad, original); err == nil || len(wire) != 0 {
			t.Fatal("an invalid preview target admitted a sealed profile")
		}
	}
}

func TestProxyOIDCEvidenceReadsOnlyExplicitlyRetainedKeys(t *testing.T) {
	codec, clock, crypto, binding, original := proxyOIDCEvidenceFixture(t)
	wire, err := codec.Seal(context.Background(), binding, original)
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := NewProxyOIDCEvidenceCodec(crypto, clock, "proxy-v2", []string{"proxy-v1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Open(context.Background(), binding, wire); err != nil {
		t.Fatal("explicitly retained original key could not open evidence", err)
	}
	retired, err := NewProxyOIDCEvidenceCodec(crypto, clock, "proxy-v2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := retired.Open(context.Background(), binding, wire); err == nil || got != (ProviderIdentity{}) {
		t.Fatal("available but unretained original key disclosed provider identity")
	}
}
