package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func oauthCallbackDenialOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "identity.oauth.callback.denied-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func anonymousOAuthCallbackDenialOperation() identity.FeatureOperation {
	op := oauthCallbackDenialOperation()
	op.SchemaID = "identity.oauth.callback.anonymous-denied-v1"
	op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	return op
}

func oauthCallbackDenialSelected(op identity.FeatureOperation) bool {
	return op == oauthCallbackDenialOperation() || op == anonymousOAuthCallbackDenialOperation()
}

func validOAuthCallbackDenialBinding(b identity.CommandBinding) bool {
	return b.ValidateFor(oauthCallbackDenialOperation()) == nil || b.ValidateFor(anonymousOAuthCallbackDenialOperation()) == nil
}

func oauthCallbackDenialDescriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.callback-denial", Version: 1}
}

// A provider-error callback terminalizes only its original RP transaction. It
// cannot issue credentials, mutate identity or borrow another proof purpose.
// HTTP provider/IP/transaction admission precedes this cancellation path; unlike
// successful linking, cancellation performs no protected credential mutation.
func encodeOAuthCallbackDenialPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	owner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if p.Feature == nil || !oauthCallbackDenialSelected(p.Feature.Operation) || p.Feature.Contributor != oauthCallbackDenialDescriptor() || !validOAuthCallbackDenialBinding(b) || p.SubjectType != "oauth_transaction" || p.Capability == nil || validateCapabilityPlan(b, p.Capability) != nil || p.RiskEvidence != nil || p.CommandCounters != nil || p.OTP != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.SignupAcceptance || p.MagicLinkRequestAcceptance || p.CapabilityIssuance != nil || p.Delivery != nil || p.OrganizationInvitationOrigin != nil || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "oauth.rp_transaction.denied.v1", BeforeVersion: 1, AfterVersion: 2}) || len(p.Contributors) != 5 || p.Contributors[4] != owner || len(p.Audits) != 1 || p.Audits[0].EventType != "identity.oauth.handle_callback" || p.Audits[0].RetentionClass != "standard" {
		return nil, invalidPlan()
	}
	user := p.Feature.Operation == oauthCallbackDenialOperation() && b.ActorKind == authorization.SubjectUser && string(b.ActorID) == string(b.UserID)
	anonymous := p.Feature.Operation == anonymousOAuthCallbackDenialOperation() && b.ActorKind == authorization.SubjectServiceAccount && b.UserID == "" && b.AnonymousFlowID != ""
	if !user && !anonymous {
		return nil, invalidPlan()
	}
	base := p
	base.Capability, base.Contributors = nil, p.Contributors[:4]
	wire, err := encodeFeaturePlanMode(b, fp, base, true)
	if err != nil {
		return nil, err
	}
	encoded := cborMap(map[string][]byte{
		"base": cborBytes(wire), "profile": cborText("identity-oauth-callback-denial-v1"), "version": cborUint(1),
		"capability":  encodeCapabilityPlan(p.Capability),
		"contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))}),
	})
	if len(encoded) > 65536 {
		return nil, invalidPlan()
	}
	return encoded, nil
}

func decodeOAuthCallbackDenialPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	// Exactly one ordinary feature map; an attacker cannot nest envelopes to
	// turn this bounded historical parser into a recursive proof interpreter.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != 0xa8 {
		return fail()
	}
	base, err := decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText("identity-oauth-callback-denial-v1"))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	p := &CapabilityPlan{Purpose: "identity.oauth.callback"}
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
	canonical, err := encodeOAuthCallbackDenialPlan(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
