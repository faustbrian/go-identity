package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
)

const ssoSAMLLogoutRelaySettlementPlanProfile = "identity-sso-saml-logout-relay-settle-v1"
const ordinaryFeaturePlanWithSubjectMap = 0xa8 // Canonical CBOR map with eight fields.

func encodeSSOSAMLLogoutRelaySettlementPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	owner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if !validSSOSAMLLogoutRelaySettlementBinding(b) || p.Feature == nil ||
		*p.Feature != (FeatureRegistration{Operation: SSOSAMLLogoutRelaySettlementOperation(), Contributor: SSOSAMLLogoutRelaySettlementDescriptor()}) ||
		p.SubjectType != ssoSAMLLogoutRequestSubject || p.Lifecycle == nil || *p.Lifecycle != SSOSAMLLogoutRelaySettlementLifecycle() ||
		len(p.Audits) != 1 || p.Audits[0].EventType != ssoSAMLLogoutRelaySettlePurpose || p.Audits[0].RetentionClass != "protected" ||
		p.Capability == nil || validateCapabilityPlan(b, p.Capability) != nil || !validSAMLLogoutRelayInstant(p.Capability.ExpiresAt) ||
		len(p.Contributors) != 5 || p.Contributors[4] != owner || p.RiskEvidence != nil || p.CommandCounters != nil || p.OTP != nil ||
		p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.CapabilityIssuance != nil || p.Delivery != nil ||
		p.SignupAcceptance || p.MagicLinkRequestAcceptance || p.OrganizationInvitationOrigin != nil {
		return nil, invalidPlan()
	}
	base := p
	base.Capability, base.Contributors = nil, p.Contributors[:4]
	wire, err := encodeFeaturePlanMode(b, fp, base, true)
	if err != nil {
		return nil, err
	}
	if len(wire) == 0 || wire[0] != ordinaryFeaturePlanWithSubjectMap {
		return nil, invalidPlan()
	}
	encoded := cborMap(map[string][]byte{
		"base": cborBytes(wire), "profile": cborText(ssoSAMLLogoutRelaySettlementPlanProfile), "version": cborUint(1),
		"capability":  encodeCapabilityPlan(p.Capability),
		"contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))}),
	})
	if len(encoded) > 65536 {
		return nil, invalidPlan()
	}
	return encoded, nil
}

func decodeSSOSAMLLogoutRelaySettlementPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	// The private base is exactly the ordinary feature map with a subject,
	// never another consumption envelope or a still-active proof declaration.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != ordinaryFeaturePlanWithSubjectMap {
		return fail()
	}
	base, err := decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText(ssoSAMLLogoutRelaySettlementPlanProfile))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	p := &CapabilityPlan{Purpose: ssoSAMLLogoutRelaySettlePurpose}
	r.key("purpose")
	r.consume(cborText(string(p.Purpose)))
	r.key("max_uses")
	p.MaxUses = uint32(r.number(math.MaxUint32))
	r.key("expires_at")
	p.ExpiresAt = time.Unix(int64(r.number(253402300799)), 0).UTC()
	r.key("capability_id")
	p.CapabilityID = r.string(256)
	r.key("replay_digest")
	r.digest(&p.ReplayDigest)
	r.key("proof_fingerprint")
	r.digest(&p.ProofFingerprint)
	r.key("replay_key_version")
	p.ReplayKeyVersion = uint32(r.number(math.MaxUint32))
	r.key("contributor")
	owner := readFeaturePlanContributor(&r)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	base.Capability, base.Contributors = p, append(base.Contributors, owner)
	canonical, err := encodeSSOSAMLLogoutRelaySettlementPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
