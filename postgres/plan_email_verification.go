package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func registrationEmailVerificationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Preserve the original signed identifier purpose while admitting only the
// distinct native registration confirmation declaration. This is not a generic
// purpose alias and grants no reservation or current account authority.
func encodeEmailVerificationPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	owner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if p.Feature == nil || p.Feature.Operation != registrationEmailVerificationOperation() || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || p.SubjectType != "identifier" || p.Capability == nil || p.Capability.Purpose != "identity.identifier.verify" || p.CommandCounters == nil || p.RiskEvidence != nil || p.OTP != nil || p.SignupAcceptance || p.CapabilityIssuance != nil || p.Delivery != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "identifier.verified.v1" || p.Lifecycle.BeforeVersion == 0 || len(p.Contributors) == 0 || p.Contributors[len(p.Contributors)-1] != owner {
		return nil, invalidPlan()
	}
	for _, a := range p.Audits {
		if a.RetentionClass != "protected" {
			return nil, invalidPlan()
		}
	}
	proofBinding := b
	proofBinding.OperationID = "identity.identifier.verify"
	if validateCapabilityPlan(proofBinding, p.Capability) != nil {
		return nil, invalidPlan()
	}
	base := p
	base.Capability = nil
	base.Contributors = p.Contributors[:len(p.Contributors)-1]
	wire, err := encodeFeaturePlan(b, fp, base)
	if err != nil {
		return nil, err
	}
	result := cborMap(map[string][]byte{
		"base": cborBytes(wire), "profile": cborText("identity-registration-email-proof-v1"), "version": cborUint(1),
		"capability":  encodeCapabilityPlan(p.Capability),
		"contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))}),
	})
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeEmailVerificationPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	// The base must be an ordinary feature profile, not another optional
	// envelope. Check before recursive decoding or narrowing an untrusted size.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] < 0xa7 || r.data[0] > 0xab {
		return fail()
	}
	base, err := decodeFeaturePlan(b, fp, r.data[:int(n)])
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText("identity-registration-email-proof-v1"))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	v := &CapabilityPlan{}
	r.key("purpose")
	r.consume(cborText("identity.identifier.verify"))
	v.Purpose = "identity.identifier.verify"
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
	canonical, err := encodeEmailVerificationPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
