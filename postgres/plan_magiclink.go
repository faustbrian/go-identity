package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func magicLinkConsumeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.consume", SchemaID: "magic-link-consume", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// This closed login envelope enlists the existing one-use participant, not a
// second replay authority. The proof-free base is private to this fixed-depth
// grammar and cannot be admitted as a standalone login declaration.
func encodeMagicLinkConsumptionPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if validateMagicLinkRegistrationPlan(b, p) != nil {
		return nil, invalidPlan()
	}
	owner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if p.Feature == nil || p.Feature.Operation != magicLinkConsumeOperation() || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || p.SubjectType != "authentication_attempt" || p.Capability == nil || p.RiskEvidence != nil || p.OTP != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.SignupAcceptance || p.CapabilityIssuance != nil || p.Delivery != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "session.created.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 0 || len(p.Contributors) == 0 || p.Contributors[len(p.Contributors)-1] != owner || validateCapabilityPlan(b, p.Capability) != nil {
		return nil, invalidPlan()
	}
	for _, a := range p.Audits {
		if a.RetentionClass != "protected" {
			return nil, invalidPlan()
		}
	}
	base := p
	base.MagicLinkRegistration = nil
	base.Capability = nil
	base.Contributors = p.Contributors[:len(p.Contributors)-1]
	wire, err := encodeFeaturePlanMode(b, fp, base, true)
	if err != nil {
		return nil, err
	}
	fields := map[string][]byte{"base": cborBytes(wire), "profile": cborText("identity-magic-link-consumption-v1"), "version": cborUint(1), "capability": encodeCapabilityPlan(p.Capability), "contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))})}
	if p.MagicLinkRegistration != nil {
		fields["signup"] = encodeMagicLinkRegistrationPlan(p.MagicLinkRegistration)
		fields["profile"] = cborText("identity-magic-link-registration-v1")
	}
	result := cborMap(fields)
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeMagicLinkConsumptionPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	count, valid := r.head(5)
	if !valid || count != 5 && count != 6 {
		return fail()
	}
	r.key("base")
	n, ok := r.head(2)
	// Accept the ordinary authentication-admission base and historical charged
	// counter base only. Neither permits recursive optional envelopes. The
	// registry and execution separately require retained native admission when
	// counters are absent; decoding alone establishes no login permission.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != 0xa8 && r.data[0] != 0xa9 {
		return fail()
	}
	base, err := decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	profile := "identity-magic-link-consumption-v1"
	if count == 6 {
		r.key("signup")
		r.expect(5, 5)
		registration := &MagicLinkRegistrationPlan{}
		r.key("user_id")
		registration.UserID = identity.UserID(r.string(128))
		r.key("event_index")
		registration.CreationEventIndex = uint16(r.number(math.MaxUint16))
		r.key("identifier_id")
		registration.IdentifierID = r.string(128)
		r.key("policy_version")
		registration.EmailPossessionPolicyVersion = r.number(math.MaxUint64)
		r.key("creation_digest")
		r.digest(&registration.CreationDigest)
		base.MagicLinkRegistration = registration
		profile = "identity-magic-link-registration-v1"
	}
	r.key("profile")
	r.consume(cborText(profile))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	v := &CapabilityPlan{}
	r.key("purpose")
	r.consume(cborText("identity.magic-link.consume"))
	v.Purpose = "identity.magic-link.consume"
	r.key("max_uses")
	v.MaxUses = uint32(r.number(math.MaxUint32))
	r.key("expires_at")
	v.ExpiresAt = time.Unix(int64(r.number(253402300799)), 0).UTC()
	r.key("capability_id")
	v.CapabilityID = r.string(256)
	r.key("replay_digest")
	r.digest(&v.ReplayDigest)
	r.key("proof_fingerprint")
	r.digest(&v.ProofFingerprint)
	r.key("replay_key_version")
	v.ReplayKeyVersion = uint32(r.number(math.MaxUint32))
	r.key("contributor")
	owner := readFeaturePlanContributor(&r)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	base.Capability = v
	base.Contributors = append(base.Contributors, owner)
	canonical, err := encodeMagicLinkConsumptionPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
