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

func managedEmailVerificationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-confirm", SchemaID: "identity.email.verification-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func managedEmailChangeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.change-confirm", SchemaID: "identity.email.change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func managedEmailConfirmationOperation(op identity.FeatureOperation) bool {
	return op == managedEmailVerificationOperation() || op == managedEmailChangeOperation()
}

func emailVerificationPlanProfile(b identity.CommandBinding) (identity.FeatureOperation, string) {
	if b.SchemaID == managedEmailChangeOperation().SchemaID {
		return managedEmailChangeOperation(), "identity-managed-email-change-proof-v1"
	}
	if b.SchemaID == managedEmailVerificationOperation().SchemaID {
		return managedEmailVerificationOperation(), "identity-managed-email-proof-v1"
	}
	return registrationEmailVerificationOperation(), "identity-registration-email-proof-v1"
}

// Preserve the original signed identifier purpose while admitting only the
// distinct native registration confirmation declaration. This is not a generic
// purpose alias and grants no reservation or current account authority.
func encodeEmailVerificationPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	owner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	op, profile := emailVerificationPlanProfile(b)
	proofIndex := len(p.Contributors) - 1
	event := "identifier.verified.v1"
	if op == managedEmailChangeOperation() {
		event = "identifier.primary-changed.v1"
		if !validDeliveryPlan(p.Delivery) || len(p.Delivery.Intents) != 1 || p.Delivery.Intents[0].Purpose != "identity.email.change-notification" || p.Delivery.Intents[0].SubjectID != string(b.UserID) || len(p.Contributors) < 2 || p.Contributors[len(p.Contributors)-1] != p.Delivery.Contributor {
			return nil, invalidPlan()
		}
		proofIndex--
	} else if p.Delivery != nil {
		return nil, invalidPlan()
	}
	if p.Feature == nil || p.Feature.Operation != op || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) || p.SubjectType != "identifier" || p.Capability == nil || p.Capability.Purpose != "identity.identifier.verify" || p.CommandCounters == nil || p.RiskEvidence != nil || p.OTP != nil || p.SignupAcceptance || p.CapabilityIssuance != nil || p.Lifecycle == nil || p.Lifecycle.EventType != event || p.Lifecycle.BeforeVersion == 0 || proofIndex < 0 || p.Contributors[proofIndex] != owner {
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
	base.Contributors = append(append([]ContributorDescriptor(nil), p.Contributors[:proofIndex]...), p.Contributors[proofIndex+1:]...)
	wire, err := encodeFeaturePlan(b, fp, base)
	if err != nil {
		return nil, err
	}
	result := cborMap(map[string][]byte{
		"base": cborBytes(wire), "profile": cborText(profile), "version": cborUint(1),
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
	change := b.SchemaID == managedEmailChangeOperation().SchemaID
	validBase := len(r.data) > 0 && r.data[0] >= 0xa7 && r.data[0] <= 0xab
	if change {
		validBase = len(r.data) > 0 && r.data[0] == 0xa3
	}
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || !validBase {
		return fail()
	}
	var base CommandPlan
	var err error
	if change {
		// The only extra layer is the old-notification delivery envelope, whose
		// base must be ordinary feature bytes. Do not allow proof -> delivery ->
		// proof recursion to bypass the fixed-depth parser boundary.
		plain := func(binding identity.CommandBinding, fingerprint [32]byte, wire []byte) (CommandPlan, error) {
			if len(wire) == 0 || wire[0] < 0xa7 || wire[0] > 0xab {
				return fail()
			}
			return decodeFeaturePlan(binding, fingerprint, wire)
		}
		base, err = decodeDeliveryWrappedPlan(b, fp, r.data[:int(n)], plain, encodeFeaturePlan)
	} else {
		base, err = decodeFeaturePlan(b, fp, r.data[:int(n)])
	}
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	_, profile := emailVerificationPlanProfile(b)
	r.consume(cborText(profile))
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
	if change {
		if len(base.Contributors) == 0 || base.Delivery == nil {
			return fail()
		}
		last := base.Contributors[len(base.Contributors)-1]
		base.Contributors = append(base.Contributors[:len(base.Contributors)-1], owner, last)
	} else {
		base.Contributors = append(base.Contributors, owner)
	}
	canonical, err := encodeEmailVerificationPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
