package postgres

import (
	"context"
	"encoding/base64"
	"encoding/binary"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

const proxyPreviewBindingCaveat = "identity.oauth.proxy.preview-binding"
const proxyPreviewProofLimit = 32768

func proxyPreviewGrantPayload(l proxyPreviewBindingLocator, issuer, audience string, binding [32]byte) capability.Payload {
	return capability.Payload{
		Version: 1, Issuer: issuer, Audiences: []string{audience}, Operation: "identity.oauth.callback",
		Tenant: string(l.Tenant), Subject: string(l.Flow), Resource: string(l.Flow), CorrelationID: string(l.OriginCommand),
		IssuedAt: l.IssuedAt, NotBefore: l.IssuedAt, ExpiresAt: l.ExpiresAt, MaxUses: 1,
		Caveats: map[string]string{proxyPreviewBindingCaveat: base64.RawURLEncoding.EncodeToString(binding[:])},
	}
}

func matchesProxyPreviewGrant(l proxyPreviewBindingLocator, issuer, audience string, binding [32]byte, p capability.Payload) bool {
	return binding != ([32]byte{}) && p.Version == 1 && p.Issuer == issuer && len(p.Audiences) == 1 && p.Audiences[0] == audience &&
		p.Operation == "identity.oauth.callback" && p.Tenant == string(l.Tenant) && p.Subject == string(l.Flow) &&
		p.Resource == string(l.Flow) && p.CorrelationID == string(l.OriginCommand) && !p.Bearer && p.MaxUses == 1 &&
		p.IssuedAt.Equal(l.IssuedAt) && p.NotBefore.Equal(l.IssuedAt) && p.ExpiresAt.Equal(l.ExpiresAt) &&
		len(p.Caveats) == 1 && p.Caveats[proxyPreviewBindingCaveat] == base64.RawURLEncoding.EncodeToString(binding[:])
}

func proxyPreviewProofAAD(binding [32]byte) (envelope.Context, error) {
	if binding == ([32]byte{}) {
		return envelope.Context{}, identity.ForbiddenError{}
	}
	return envelope.NewContext(map[string]string{"profile": "identity-oauth-postgres-preview-proof-v1", "binding": base64.RawURLEncoding.EncodeToString(binding[:])})
}

func (s *ProxyPreviewService) openGrant(ctx context.Context, row proxyPreviewRow, binding [32]byte, expected identity.CommandBinding) (kernel.CapabilityPlan, error) {
	var zero kernel.CapabilityPlan
	aad, err := proxyPreviewProofAAD(binding)
	if err != nil {
		return zero, err
	}
	start := s.signin.start
	plain, err := start.open(ctx, aad, row.proof, proxyPreviewProofLimit)
	defer clear(plain)
	if err != nil || len(plain) <= 5 || plain[0] != 1 {
		return zero, identity.ForbiddenError{}
	}
	replay := binary.BigEndian.Uint32(plain[1:5])
	proof, err := capability.ParseProof(string(plain[5:]), start.config.Capability.Crypto.Limits)
	if err != nil || replay == 0 {
		return zero, identity.ForbiddenError{}
	}
	defer func() {
		_ = proof.Transfer(context.WithoutCancel(ctx), func(context.Context, []byte) error { return nil })
	}()
	issuer, audience := start.config.Capability.Crypto.Issuer, start.config.Capability.Audience
	checked, err := s.crypto.Verify(ctx, proof, "identity.oauth.callback", audience)
	if err != nil || !matchesProxyPreviewGrant(row.locator, issuer, audience, binding, checked.Payload()) {
		return zero, identity.ForbiddenError{}
	}
	plan, err := start.issuer.PrepareOAuthCallbackConsumption(ctx, expected, proof, replay)
	if err != nil || plan.ProofFingerprint != checked.EnvelopeDigest() {
		return zero, identity.ForbiddenError{}
	}
	return plan, nil
}
