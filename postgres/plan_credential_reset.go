package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func encodeCredentialResetPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	owner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	phone := phoneResetConsumptionPlan(p)
	if p.Feature == nil || !phone && (p.Feature.Operation != credentialResetOperation() || p.RiskEvidence != nil || p.OTP != nil) || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) || p.SubjectType != "credential" || p.Capability == nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.SignupAcceptance || p.CapabilityIssuance != nil || p.Delivery != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "password.reset.v1" || p.Lifecycle.BeforeVersion == 0 || len(p.Contributors) == 0 || p.Contributors[len(p.Contributors)-1] != owner || validateCapabilityPlan(b, p.Capability) != nil {
		return nil, invalidPlan()
	}
	for _, a := range p.Audits {
		if a.RetentionClass != "protected" {
			return nil, invalidPlan()
		}
	}
	base := p
	base.Capability = nil
	base.Contributors = p.Contributors[:len(p.Contributors)-1]
	wire, err := encodeFeaturePlanMode(b, fp, base, true)
	if err != nil {
		return nil, err
	}
	profile := "identity-password-reset-proof-v1"
	if phone {
		profile = "identity-phone-password-reset-proof-v1"
	}
	result := cborMap(map[string][]byte{"base": cborBytes(wire), "profile": cborText(profile), "version": cborUint(1), "capability": encodeCapabilityPlan(p.Capability), "contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))})})
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeCredentialResetPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	phone := b.OperationID == "identity.phone.password-reset-complete"
	// Reset's base is exactly ordinary protected feature grammar, with either
	// historical command counters or the native Authentication admission lane;
	// wrappers cannot recursively nest or allocate beyond the original input.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || phone && r.data[0] != 0xaa || !phone && r.data[0] != 0xa8 && r.data[0] != 0xa9 {
		return fail()
	}
	base, err := decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	profile, purpose := "identity-password-reset-proof-v1", "identity.password.reset-complete"
	if phone {
		profile, purpose = "identity-phone-password-reset-proof-v1", "identity.phone.password-reset-complete"
	}
	r.consume(cborText(profile))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	v := &CapabilityPlan{}
	r.key("purpose")
	r.consume(cborText(purpose))
	v.Purpose = capability.Purpose(purpose)
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
	canonical, err := encodeCredentialResetPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
