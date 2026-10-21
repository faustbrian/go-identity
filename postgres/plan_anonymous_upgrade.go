package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func anonymousUpgradeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.upgrade", SchemaID: "identity.anonymous.upgrade.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// This envelope is a closed declaration, not target authentication or guest
// possession. User/actor remain the permanent target; RecordID is the distinct
// guest. The native owner must validate both original credentials and retain
// their earliest expiry. The existing capability participant owns one-time use.
func encodeAnonymousUpgradePlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	owner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if p.Feature == nil || p.Feature.Operation != anonymousUpgradeOperation() || p.Feature.Contributor != anonymousCreationDescriptor() || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || b.RecordID == string(b.UserID) || p.SubjectType != "anonymous" || p.Capability == nil || validateCapabilityPlan(b, p.Capability) != nil || p.CommandCounters == nil || p.RiskEvidence != nil || p.OTP != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.SignupAcceptance || p.MagicLinkRequestAcceptance || p.CapabilityIssuance != nil || p.Delivery != nil || p.OrganizationInvitationOrigin != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "anonymous.upgraded.v1" || p.Lifecycle.BeforeVersion == 0 || p.Lifecycle.BeforeVersion == math.MaxUint64 || p.Lifecycle.EventIndex != 0 || len(p.Contributors) == 0 || p.Contributors[len(p.Contributors)-1] != owner || len(p.Audits) != 1 || p.Audits[0].EventType != "identity.anonymous.upgrade" || p.Audits[0].RetentionClass != "protected" {
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
		"base": cborBytes(wire), "profile": cborText("identity-anonymous-upgrade-consumption-v1"), "version": cborUint(1),
		"capability":  encodeCapabilityPlan(p.Capability),
		"contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))}),
	})
	if len(encoded) > 65536 {
		return nil, invalidPlan()
	}
	return encoded, nil
}

func decodeAnonymousUpgradePlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	// The base is one ordinary bounded feature map. Never recursively decode an
	// optional envelope or admit its proof-free base as a public upgrade plan.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] < 0xa7 || r.data[0] > 0xab {
		return fail()
	}
	base, err := decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText("identity-anonymous-upgrade-consumption-v1"))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	p := &CapabilityPlan{}
	r.key("purpose")
	r.consume(cborText("identity.anonymous.upgrade"))
	p.Purpose = "identity.anonymous.upgrade"
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
	canonical, err := encodeAnonymousUpgradePlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
