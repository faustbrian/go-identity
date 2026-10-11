package postgres

import (
	"bytes"
	"crypto/sha256"

	identity "github.com/faustbrian/go-identity"
)

const signupAcceptedEvent = "identity.password.signup.accepted.v1"
const signupAcceptanceProfile = "identity-password-signup-acceptance-v1"
const magicLinkRequestAcceptanceProfile = "identity-magic-link-request-acceptance-v1"

// The wrapper explicitly freezes both possible lifecycle branches while
// preserving every byte of the legacy creation declaration. Its presence is
// never inferred from an absent user or from a contributor's provisional result.
func encodeSignupAcceptancePlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if p.MagicLinkRequestAcceptance {
		return nil, invalidPlan()
	}
	if p.Feature == nil || !passwordRegistrationOperation(p.Feature.Operation) || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) || p.Feature.Operation.SubjectRequirement != identity.FeatureSubjectAnonymousFlow || b.UserID != "" || b.AnonymousFlowID == "" || p.SubjectType != "user" || p.Lifecycle == nil || p.Lifecycle.EventType != "user.created.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 0 || len(p.Audits) == 0 || p.Audits[0].RetentionClass != "protected" {
		return nil, invalidPlan()
	}
	p.SignupAcceptance = false
	return encodeAcceptanceBase(b, fp, p, signupAcceptanceProfile)
}

func encodeMagicLinkRequestAcceptancePlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if p.SignupAcceptance || p.Feature == nil || !magicLinkRequestOperation(p.Feature.Operation) || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || b.UserID != "" || b.AnonymousFlowID == "" || p.SubjectType != "user" || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "magic-link.requested.v1"}) || len(p.Audits) == 0 || p.Audits[0].RetentionClass != "protected" || p.Capability != nil || p.MagicLinkRegistration != nil || p.RiskEvidence != nil || p.OTP != nil {
		return nil, invalidPlan()
	}
	if p.CapabilityIssuance != nil && (p.CapabilityIssuance.MagicLinkRecipientUserID == "" || !validMagicLinkRecipientIssuance(b, p)) || p.Delivery != nil && p.CapabilityIssuance == nil {
		return nil, invalidPlan()
	}
	p.MagicLinkRequestAcceptance = false
	return encodeAcceptanceBase(b, fp, p, magicLinkRequestAcceptanceProfile)
}

func encodeAcceptanceBase(b identity.CommandBinding, fp [32]byte, p CommandPlan, profile string) ([]byte, error) {
	base, err := encodeFeaturePlan(b, fp, p)
	if err != nil || len(base) > 65000 {
		return nil, invalidPlan()
	}
	return cborMap(map[string][]byte{"base": cborBytes(base), "profile": cborText(profile)}), nil
}

func decodeSignupAcceptancePlan(b identity.CommandBinding, fp [32]byte, wire []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(wire) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: wire}, ok: true}
	r.expect(5, 2)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > 65000 || n > uint64(len(r.data)) || r.data[0] == 0xa2 {
		return fail()
	}
	base := r.data[:int(n)]
	if !signupAcceptanceBaseBounded(base) {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	profile, valid := r.text(128)
	if !r.ok || !valid || len(r.data) != 0 || profile != signupAcceptanceProfile && profile != magicLinkRequestAcceptanceProfile {
		return fail()
	}
	p, err := decodeFeaturePlan(b, fp, base)
	if err != nil {
		return fail()
	}
	p.SignupAcceptance = profile == signupAcceptanceProfile
	p.MagicLinkRequestAcceptance = profile == magicLinkRequestAcceptanceProfile
	canonical, err := encodeFeaturePlan(b, fp, p)
	if err != nil || !bytes.Equal(canonical, wire) {
		return fail()
	}
	p.Digest = sha256.Sum256(wire)
	return p, nil
}

// The only valid shape is acceptance -> optional delivery -> optional issuance
// -> feature. Reject an interleaved wrapper chain before recursive decoding.
func signupAcceptanceBaseBounded(base []byte) bool {
	for _, header := range []byte{0xa3, 0xa4} {
		if len(base) == 0 {
			return false
		}
		if base[0] != header {
			continue
		}
		r := planReader{attributeReader: attributeReader{data: base}, ok: true}
		r.expect(5, uint64(header&31))
		r.key("base")
		n, ok := r.head(2)
		if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) {
			return false
		}
		base = r.data[:int(n)]
	}
	return len(base) > 0 && base[0] >= 0xa7 && base[0] <= 0xab
}
