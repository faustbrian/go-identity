package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// CapabilityIssuancePlan declares 1..16 original-command one-use issuance
// effects. Grants contain only immutable signed-envelope/replay metadata, not
// bearer bytes or authority. Their purposes select future protected operations,
// not the originating command operation. The exact capability.issuance v1 owner
// must follow the base participants and precede optional delivery. Nil preserves
// historical plan bytes. The owner must authenticate each staged Grant against
// its original envelope fingerprint and independently keyed replay digest.
type CapabilityIssuancePlan struct {
	Contributor ContributorDescriptor
	Grants      []CapabilityPlan
	// RegistrationUserID selects the frozen newly created user of native
	// anonymous password signup, not a replacement command subject. Empty
	// preserves existing command-user issuance. It grants no authority alone.
	RegistrationUserID identity.UserID
	// ResetRecipientUserID selects only the existing recipient independently
	// fenced by native anonymous reset-request execution. It is mutually
	// exclusive with RegistrationUserID and permits one reset-complete grant.
	// Metadata alone grants no selection, factor or issuance authority.
	ResetRecipientUserID identity.UserID
	// MagicLinkRecipientUserID selects an existing verified-email recipient only
	// under the anonymous magic-link request profile. It is mutually exclusive
	// with both password targets. Staging requires the same invocation's primary
	// recipient fence; this metadata grants neither authentication nor issuance.
	MagicLinkRecipientUserID identity.UserID
}

func cloneCapabilityIssuancePlan(p *CapabilityIssuancePlan) *CapabilityIssuancePlan {
	if p == nil {
		return nil
	}
	copy := *p
	copy.Grants = append([]CapabilityPlan(nil), p.Grants...)
	return &copy
}

func validCapabilityIssuancePlan(p *CapabilityIssuancePlan) bool {
	if p == nil || p.Contributor != (ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.issuance", Version: 1}) || len(p.Grants) == 0 || len(p.Grants) > 16 {
		return false
	}
	if p.RegistrationUserID != "" && (identity.User{ID: p.RegistrationUserID, TenantID: "validation", Status: identity.StatusActive, Version: 1}).Validate("validation") != nil {
		return false
	}
	if p.ResetRecipientUserID != "" && (p.RegistrationUserID != "" || (identity.User{ID: p.ResetRecipientUserID, TenantID: "validation", Status: identity.StatusActive, Version: 1}).Validate("validation") != nil) {
		return false
	}
	if p.MagicLinkRecipientUserID != "" && (p.RegistrationUserID != "" || p.ResetRecipientUserID != "" || (identity.User{ID: p.MagicLinkRecipientUserID, TenantID: "validation", Status: identity.StatusActive, Version: 1}).Validate("validation") != nil) {
		return false
	}
	for i, v := range p.Grants {
		if v.MaxUses != 1 || v.ReplayKeyVersion == 0 || v.ProofFingerprint == ([32]byte{}) || !postgresExactTime(v.ExpiresAt) || v.ExpiresAt.Unix() <= 0 || v.ExpiresAt.Nanosecond() != 0 {
			return false
		}
		if _, err := capability.NewReference(v.CapabilityID, v.Purpose, v.ReplayDigest, v.ExpiresAt); err != nil {
			return false
		}
		for _, prior := range p.Grants[:i] {
			if prior.CapabilityID == v.CapabilityID || prior.ReplayKeyVersion == v.ReplayKeyVersion && prior.ReplayDigest == v.ReplayDigest {
				return false
			}
		}
	}
	return true
}

// A target override belongs only to new-user verification from the original
// anonymous signup. It never broadens consumption or other issuance profiles.
func validRegistrationIssuance(b identity.CommandBinding, p CommandPlan) bool {
	if p.CapabilityIssuance.RegistrationUserID == "" {
		return true
	}
	if b.UserID != "" || b.AnonymousFlowID == "" || p.Feature == nil || !passwordRegistrationOperation(p.Feature.Operation) || p.Feature.Operation.SubjectRequirement != identity.FeatureSubjectAnonymousFlow || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) || p.SubjectType != "user" || p.Lifecycle == nil || *p.Lifecycle != (LifecyclePlan{EventType: "user.created.v1"}) {
		return false
	}
	for _, g := range p.CapabilityIssuance.Grants {
		if g.Purpose != "identity.identifier.verify" {
			return false
		}
	}
	return true
}

func passwordResetRequestOperation(op identity.FeatureOperation) bool {
	return op == (identity.FeatureOperation{Owner: "identity/password", OperationID: "identity.password.reset-request", SchemaID: "password-reset-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow})
}

func validResetRecipientIssuance(b identity.CommandBinding, p CommandPlan) bool {
	i := p.CapabilityIssuance
	if i.ResetRecipientUserID == "" {
		return true
	}
	return i.RegistrationUserID == "" && b.UserID == "" && b.AnonymousFlowID != "" && p.Feature != nil && passwordResetRequestOperation(p.Feature.Operation) && p.Feature.Contributor == (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}) && p.Lifecycle != nil && len(i.Grants) == 1 && i.Grants[0].Purpose == "identity.password.reset-complete"
}

func magicLinkRequestOperation(op identity.FeatureOperation) bool {
	return op == (identity.FeatureOperation{Owner: "identity/magiclink", OperationID: "identity.magic-link.request", SchemaID: "magic-link-request", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow})
}

func validMagicLinkRecipientIssuance(b identity.CommandBinding, p CommandPlan) bool {
	i := p.CapabilityIssuance
	if i.MagicLinkRecipientUserID == "" {
		return true
	}
	return i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && b.UserID == "" && b.AnonymousFlowID != "" && p.Feature != nil && magicLinkRequestOperation(p.Feature.Operation) && p.Feature.Contributor == (ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) && p.Lifecycle != nil && len(i.Grants) == 1 && i.Grants[0].Purpose == "identity.magic-link.consume"
}

// The four-field optional envelope is distinct from the existing three-field
// delivery envelope. Delivery remains outermost; a nested issuer envelope is
// forbidden. No second journal or alternative history authority is introduced.
func encodeIssuanceWrappedPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan, encode func(identity.CommandBinding, [32]byte, CommandPlan) ([]byte, error)) ([]byte, error) {
	if !validCapabilityIssuancePlan(p.CapabilityIssuance) || !validRegistrationIssuance(b, p) || !validResetRecipientIssuance(b, p) || !validMagicLinkRecipientIssuance(b, p) || p.Lifecycle == nil || len(p.Contributors) == 0 || p.Contributors[len(p.Contributors)-1] != p.CapabilityIssuance.Contributor {
		return nil, invalidPlan()
	}
	base := p
	base.Contributors = p.Contributors[:len(p.Contributors)-1]
	base.CapabilityIssuance = nil
	wire, err := encode(b, fp, base)
	if err != nil {
		return nil, err
	}
	grants := make([][]byte, len(p.CapabilityIssuance.Grants))
	for i := range grants {
		grants[i] = encodeCapabilityPlan(&p.CapabilityIssuance.Grants[i])
	}
	d := p.CapabilityIssuance.Contributor
	fields := map[string][]byte{"grants": cborArray(grants), "contributor": cborMap(map[string][]byte{"owner": cborText(d.Owner), "contract_id": cborText(d.ContractID), "version": cborUint(uint64(d.Version))})}
	if p.CapabilityIssuance.RegistrationUserID != "" {
		fields["registration_user_id"] = cborText(string(p.CapabilityIssuance.RegistrationUserID))
	}
	if p.CapabilityIssuance.ResetRecipientUserID != "" {
		fields["reset_recipient_user_id"] = cborText(string(p.CapabilityIssuance.ResetRecipientUserID))
	}
	if p.CapabilityIssuance.MagicLinkRecipientUserID != "" {
		fields["magic_link_recipient_user_id"] = cborText(string(p.CapabilityIssuance.MagicLinkRecipientUserID))
	}
	issuance := cborMap(fields)
	result := cborMap(map[string][]byte{"base": cborBytes(wire), "profile": cborText("identity-capability-issuance-v1"), "issuance": issuance, "version": cborUint(1)})
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeIssuanceWrappedPlan(b identity.CommandBinding, fp [32]byte, data []byte, decode func(identity.CommandBinding, [32]byte, []byte) (CommandPlan, error), encode func(identity.CommandBinding, [32]byte, CommandPlan) ([]byte, error)) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 4)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > 65536 || n > uint64(len(r.data)) || r.data[0] == 0xa3 || r.data[0] == 0xa4 {
		return fail()
	}
	base, err := decode(b, fp, r.data[:int(n)])
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText("identity-capability-issuance-v1"))
	r.key("version")
	r.consume(cborUint(1))
	r.key("issuance")
	fieldCount, fieldsOK := r.head(5)
	if !fieldsOK || fieldCount != 2 && fieldCount != 3 {
		return fail()
	}
	r.key("grants")
	count, ok := r.head(4)
	if !r.ok || !ok || count == 0 || count > 16 {
		return fail()
	}
	p := &CapabilityIssuancePlan{Grants: make([]CapabilityPlan, int(count))}
	for i := range p.Grants {
		v := &p.Grants[i]
		r.expect(5, 7)
		r.key("purpose")
		v.Purpose = capability.Purpose(r.string(128))
		r.key("max_uses")
		v.MaxUses = uint32(r.number(math.MaxUint32))
		r.key("expires_at")
		v.ExpiresAt = time.Unix(int64(r.number(253402300799)), 0).UTC()
		r.key("capability_id")
		v.CapabilityID = r.string(128)
		r.key("replay_digest")
		r.digest(&v.ReplayDigest)
		r.key("proof_fingerprint")
		r.digest(&v.ProofFingerprint)
		r.key("replay_key_version")
		v.ReplayKeyVersion = uint32(r.number(math.MaxUint32))
	}
	r.key("contributor")
	p.Contributor = readFeaturePlanContributor(&r)
	if fieldCount == 3 {
		switch r.string(64) {
		case "registration_user_id":
			p.RegistrationUserID = identity.UserID(r.string(128))
		case "reset_recipient_user_id":
			p.ResetRecipientUserID = identity.UserID(r.string(128))
		case "magic_link_recipient_user_id":
			p.MagicLinkRecipientUserID = identity.UserID(r.string(128))
		default:
			return fail()
		}
	}
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	base.CapabilityIssuance = p
	base.Contributors = append(base.Contributors, p.Contributor)
	canonical, err := encode(b, fp, base)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	base.Digest = sha256.Sum256(data)
	return base, nil
}
