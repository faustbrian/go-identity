package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func oauthSigninPreparation(p CommandPlan) bool {
	return p.Feature != nil && p.Feature.Operation == oauthSigninAccountOperation() && p.Feature.Contributor == (ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.signin", Version: 1}) && p.Capability != nil && p.Capability.Purpose == "identity.oauth.callback" && p.Capability.MaxUses == 1 && p.CommandCounters != nil
}

// Only this fixed-depth envelope admits callback-state consumption for native
// existing-account signin. Provider exchange and session effects remain owned
// by the native contributor, not by a second coordinator or replay authority.
func encodeOAuthSigninConsumptionPlan(b identity.CommandBinding, fingerprint [32]byte, p CommandPlan) ([]byte, error) {
	capabilityOwner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if p.Feature == nil || p.Capability == nil || p.CommandCounters == nil || p.Lifecycle == nil {
		return nil, invalidPlan()
	}
	if p.Feature.Operation != oauthSigninAccountOperation() || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.signin", Version: 1}) {
		return nil, invalidPlan()
	}
	if b.ValidateFor(p.Feature.Operation) != nil || b.ActorKind != authorization.SubjectServiceAccount || b.UserID != "" || b.RecordID != "" || b.AnonymousFlowID == "" {
		return nil, invalidPlan()
	}
	if p.SubjectType != "authentication_attempt" || validateCapabilityPlan(b, p.Capability) != nil || *p.Lifecycle != (LifecyclePlan{EventType: "session.created.v1"}) {
		return nil, invalidPlan()
	}
	if len(p.Contributors) != 6 || p.Contributors[5] != capabilityOwner || len(p.Audits) != 1 {
		return nil, invalidPlan()
	}
	if p.Audits[0].EventType != "identity.oauth.handle_callback" || p.Audits[0].RetentionClass != "protected" {
		return nil, invalidPlan()
	}
	unselectedAuthentication := p.APIKeyVerification != nil || p.MFACompletion != nil || p.MFAContinuation != nil || p.MagicLinkRegistration != nil || p.PasskeyRegistration != nil || p.SignupAcceptance || p.MagicLinkRequestAcceptance || p.IdentifierAdmission != nil
	unselectedEffects := p.OrganizationInvitationOrigin != nil || p.Delivery != nil || p.CapabilityIssuance != nil || p.AccountLinkState != nil || p.OTP != nil || p.RiskEvidence != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation
	if unselectedAuthentication || unselectedEffects {
		return nil, invalidPlan()
	}
	base := p
	base.Capability = nil
	base.Contributors = p.Contributors[:5]
	wire, err := encodeFeaturePlanMode(b, fingerprint, base, true)
	if err != nil {
		return nil, err
	}
	encoded := cborMap(map[string][]byte{
		"base": cborBytes(wire), "profile": cborText("identity-oauth-signin-consumption-v1"), "version": cborUint(1),
		"capability":  encodeCapabilityPlan(p.Capability),
		"contributor": cborMap(map[string][]byte{"owner": cborText(capabilityOwner.Owner), "contract_id": cborText(capabilityOwner.ContractID), "version": cborUint(uint64(capabilityOwner.Version))}),
	})
	if len(encoded) > 65536 {
		return nil, invalidPlan()
	}
	return encoded, nil
}

func decodeOAuthSigninConsumptionPlan(b identity.CommandBinding, fingerprint [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	count, ok := r.head(2)
	// A single ordinary counter/feature base is allowed, never another envelope.
	if !r.ok || !ok || count == 0 || count > uint64(len(r.data)) || r.data[0] != 0xa8 && r.data[0] != 0xa9 {
		return fail()
	}
	base, err := decodeFeaturePlanMode(b, fingerprint, r.data[:int(count)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(count):]
	r.key("profile")
	r.consume(cborText("identity-oauth-signin-consumption-v1"))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	proof := &CapabilityPlan{Purpose: "identity.oauth.callback"}
	r.key("purpose")
	r.consume(cborText(string(proof.Purpose)))
	r.key("max_uses")
	proof.MaxUses = uint32(r.number(math.MaxUint32))
	r.key("expires_at")
	proof.ExpiresAt = time.Unix(int64(r.number(253402300799)), 0).UTC()
	r.key("capability_id")
	proof.CapabilityID = r.string(256)
	r.key("replay_digest")
	r.digest(&proof.ReplayDigest)
	r.key("proof_fingerprint")
	r.digest(&proof.ProofFingerprint)
	r.key("replay_key_version")
	proof.ReplayKeyVersion = uint32(r.number(math.MaxUint32))
	r.key("contributor")
	owner := readFeaturePlanContributor(&r)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	base.Capability = proof
	base.Contributors = append(base.Contributors, owner)
	canonical, err := encodeOAuthSigninConsumptionPlan(b, fingerprint, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
