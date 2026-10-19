package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func organizationInvitationSendOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "organization", OperationID: "identity.organization.invitation-send", SchemaID: "organization-invitation-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
}

func organizationInvitationResendOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "organization", OperationID: "identity.organization.invitation.resend", SchemaID: "organization-invitation-resend", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
}

func organizationInvitationIssuanceOperation(op identity.FeatureOperation) bool {
	return op == organizationInvitationSendOperation() || op == organizationInvitationResendOperation()
}

func organizationInvitationAcceptOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "organization", OperationID: "identity.organization.invitation.accept", SchemaID: "organization-invitation-accept", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser}
}

func organizationInvitationDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.invitation", Version: 1}
}

// This is a closed declaration grammar, not token verification or execution
// authority. The enlisted native owner and capability participant independently
// recheck original recipient, invitation and authenticated grant custody.
func encodeOrganizationInvitationConsumptionPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if p.Lifecycle == nil || p.Lifecycle.BeforeVersion == 0 || p.Lifecycle.BeforeVersion == math.MaxUint64 {
		return nil, invalidPlan()
	}
	owner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if p.Feature == nil || p.Feature.Operation != organizationInvitationAcceptOperation() || p.Feature.Contributor != organizationInvitationDescriptor() || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || p.SubjectType != "invitation" || p.Capability == nil || validateCapabilityPlan(b, p.Capability) != nil || p.CommandCounters == nil || p.RiskEvidence != nil || p.OTP != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.SignupAcceptance || p.MagicLinkRequestAcceptance || p.CapabilityIssuance != nil || p.Delivery != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "invitation.accepted.v1" || p.Lifecycle.BeforeVersion == 0 || p.Lifecycle.EventIndex != 0 || len(p.Contributors) == 0 || p.Contributors[len(p.Contributors)-1] != owner || len(p.Audits) != 1 || p.Audits[0].EventType != "identity.organization.accept_invitation" || p.Audits[0].RetentionClass != "protected" {
		return nil, invalidPlan()
	}
	base := p
	base.Capability = nil
	base.Contributors = p.Contributors[:len(p.Contributors)-1]
	wire, err := encodeFeaturePlanMode(b, fp, base, true)
	if err != nil {
		return nil, err
	}
	encoded := cborMap(map[string][]byte{
		"base": cborBytes(wire), "profile": cborText("identity-organization-invitation-consumption-v1"), "version": cborUint(1),
		"capability":  encodeCapabilityPlan(p.Capability),
		"contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))}),
	})
	if len(encoded) > 65536 {
		return nil, invalidPlan()
	}
	return encoded, nil
}

func decodeOrganizationInvitationConsumptionPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	// Only an ordinary bounded feature map may be the private proof-free base;
	// optional-envelope discriminators cannot recursively nest this profile.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] < 0xa7 || r.data[0] > 0xab {
		return fail()
	}
	base, err := decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText("identity-organization-invitation-consumption-v1"))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	p := &CapabilityPlan{}
	r.key("purpose")
	r.consume(cborText("identity.organization.invitation.accept"))
	p.Purpose = "identity.organization.invitation.accept"
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
	canonical, err := encodeOrganizationInvitationConsumptionPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
