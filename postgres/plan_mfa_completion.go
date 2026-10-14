package postgres

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// MFACompletionPlan binds a named factor operation to the original partial
// authentication scope. It is metadata, not a factor proof or permission to
// issue a session. The native owner must authenticate the original scope,
// verify the selected factor, fence these versions and persist completion with
// session effects in the sole Work. ID is the original child capability ID;
// ContinuationVersion is the expected shared-attempt version, never a reset.
// Nil preserves existing feature profiles, including enrollment verification.
type MFACompletionPlan struct {
	ID                                                identity.CommandID
	UserID                                            identity.UserID
	ScopeDigest                                       [32]byte
	PolicyVersion, FactorVersion, ContinuationVersion uint64
}

// Format hides correlated authentication metadata.
func (MFACompletionPlan) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFACompletionPlan(redacted)"))
}

// MarshalJSON rejects implicit export; the kernel owns the historical codec.
func (MFACompletionPlan) MarshalJSON() ([]byte, error) { return nil, invalidPlan() }

func cloneMFACompletionPlan(p *MFACompletionPlan) *MFACompletionPlan {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}

func mfaCompletionOperation(op identity.FeatureOperation) bool {
	method := ""
	switch op.OperationID {
	case "identity.mfa.totp-verify":
		method = "totp-verify"
	case "identity.mfa.otp-verify":
		method = "otp-verify"
	case "identity.mfa.recovery-use":
		method = "recovery-use"
	case "identity.mfa.security-key-assert-verify":
		method = "security-key-assert-verify"
	default:
		return false
	}
	return op == (identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa." + method, SchemaID: "mfa-" + method, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow})
}

func mfaCompletionPurpose(operation string) bool {
	switch operation {
	case "identity.mfa.totp-verify", "identity.mfa.otp-verify", "identity.mfa.recovery-use", "identity.mfa.security-key-assert-verify":
		return true
	}
	return false
}

func validMFACompletionPlan(b identity.CommandBinding, p CommandPlan) bool {
	m := p.MFACompletion
	if m == nil || p.Feature == nil || !mfaCompletionOperation(p.Feature.Operation) || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || b.UserID != "" || b.AnonymousFlowID == "" || p.SubjectType != "authentication_attempt" || p.MFAContinuation != nil || p.MagicLinkRegistration != nil || p.MagicLinkRequestAcceptance || p.SignupAcceptance || p.CapabilityIssuance != nil || p.Delivery != nil || p.RiskEvidence != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.IdentifierAdmission != nil || p.Capability == nil || p.Capability.Purpose != "identity.mfa.complete" || validateCapabilityPlan(b, p.Capability) != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "session.created.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 0 || len(p.Contributors) == 0 {
		return false
	}
	if _, err := identity.ParseCommandID(string(m.ID)); err != nil {
		return false
	}
	if p.Capability.CapabilityID != string(m.ID) || m.ScopeDigest == ([32]byte{}) || m.PolicyVersion == 0 || m.FactorVersion == 0 || m.ContinuationVersion == 0 || (identity.User{ID: m.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}).Validate(b.TenantID) != nil {
		return false
	}
	if p.Feature.Operation.OperationID == "identity.mfa.otp-verify" {
		if p.OTP == nil || p.OTP.Mode != OTPConsume {
			return false
		}
	} else if p.OTP != nil {
		return false
	}
	return p.Contributors[len(p.Contributors)-1] == (ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1})
}

func encodeMFACompletionPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	if !validMFACompletionPlan(b, p) {
		return nil, invalidPlan()
	}
	for _, a := range p.Audits {
		if a.RetentionClass != "protected" {
			return nil, invalidPlan()
		}
	}
	base := p
	base.MFACompletion, base.Capability = nil, nil
	base.Contributors = p.Contributors[:len(p.Contributors)-1]
	wire, err := encodeFeaturePlanMode(b, fp, base, true)
	if err != nil {
		return nil, err
	}
	m := p.MFACompletion
	owner := p.Contributors[len(p.Contributors)-1]
	result := cborMap(map[string][]byte{
		"base": cborBytes(wire), "profile": cborText("identity-mfa-completion-v1"), "version": cborUint(1),
		"completion": cborMap(map[string][]byte{"id": cborText(string(m.ID)), "user_id": cborText(string(m.UserID)), "scope_digest": cborBytes(m.ScopeDigest[:]), "policy_version": cborUint(m.PolicyVersion), "factor_version": cborUint(m.FactorVersion), "continuation_version": cborUint(m.ContinuationVersion)}),
		"capability": encodeCapabilityPlan(p.Capability), "contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))}),
	})
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeMFACompletionPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 6)
	r.key("base")
	n, ok := r.head(2)
	// Only the ordinary fixed-depth feature base is allowed. It cannot recursively
	// carry another proof, issuer or delivery envelope.
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] < 0xa8 || r.data[0] > 0xab {
		return fail()
	}
	p, err := decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	r.consume(cborText("identity-mfa-completion-v1"))
	r.key("version")
	r.consume(cborUint(1))
	r.key("capability")
	r.expect(5, 7)
	v := &CapabilityPlan{}
	r.key("purpose")
	r.consume(cborText("identity.mfa.complete"))
	v.Purpose = "identity.mfa.complete"
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
	r.key("completion")
	r.expect(5, 6)
	m := &MFACompletionPlan{}
	r.key("id")
	m.ID = identity.CommandID(r.string(22))
	r.key("user_id")
	m.UserID = identity.UserID(r.string(128))
	r.key("scope_digest")
	r.digest(&m.ScopeDigest)
	r.key("factor_version")
	m.FactorVersion = r.number(math.MaxUint64)
	r.key("policy_version")
	m.PolicyVersion = r.number(math.MaxUint64)
	r.key("continuation_version")
	m.ContinuationVersion = r.number(math.MaxUint64)
	r.key("contributor")
	owner := readFeaturePlanContributor(&r)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	p.Capability, p.MFACompletion = v, m
	p.Contributors = append(p.Contributors, owner)
	canonical, err := encodeMFACompletionPlan(b, fp, p)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	p.Digest = sha256.Sum256(data)
	return p, nil
}
