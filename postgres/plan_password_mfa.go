package postgres

import (
	"bytes"
	"crypto/sha256"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func passwordMFAOperation(p CommandPlan) bool {
	return p.Feature != nil && passwordSigninOperation(p.Feature.Operation) && p.Feature.Operation.SubjectRequirement == identity.FeatureSubjectAnonymousFlow && p.Feature.Contributor == (ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1})
}

func encodeMFAContinuationPlanMode(b identity.CommandBinding, fp [32]byte, p CommandPlan, allowUngenerated bool) ([]byte, error) {
	if emailVerificationMFAOperation(p) {
		return encodePrimaryMFAPlanMode(b, fp, p, "email-verification", allowUngenerated)
	}
	if passwordMFAOperation(p) {
		return encodePasswordMFAPlanMode(b, fp, p, allowUngenerated)
	}
	return encodeMagicLinkMFAPlanMode(b, fp, p, allowUngenerated)
}

func decodeMFAContinuationPlanMode(b identity.CommandBinding, fp [32]byte, data []byte, allowUngenerated bool) (CommandPlan, error) {
	if b.OperationID == "identity.email.verification-signin" {
		return decodePrimaryMFAPlanMode(b, fp, data, "email-verification", allowUngenerated)
	}
	if b.OperationID == "identity.password.signin" {
		return decodePasswordMFAPlanMode(b, fp, data, allowUngenerated)
	}
	return decodeMagicLinkMFAPlanMode(b, fp, data, allowUngenerated)
}

func validMFAContinuationPlanMode(b identity.CommandBinding, p CommandPlan, allowUngenerated bool) bool {
	if emailVerificationMFAOperation(p) {
		return validEmailVerificationMFAPlanMode(b, p, allowUngenerated)
	}
	if passwordMFAOperation(p) {
		return validPasswordMFAPlanMode(b, p, allowUngenerated)
	}
	return validMagicLinkMFAPlanMode(b, p, allowUngenerated)
}

func validPasswordMFAPlanMode(b identity.CommandBinding, p CommandPlan, allowUngenerated bool) bool {
	m, i := p.MFAContinuation, p.CapabilityIssuance
	if m == nil || !passwordMFAOperation(p) || b.UserID != "" || b.AnonymousFlowID == "" || p.SubjectType != "authentication_attempt" || p.MFACompletion != nil || p.MagicLinkRegistration != nil || p.MagicLinkRequestAcceptance || p.SignupAcceptance || p.Delivery != nil || p.RiskEvidence != nil || p.OTP != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.IdentifierAdmission != nil || p.Capability != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "mfa.challenge.created.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 0 || len(p.Contributors) == 0 || (identity.User{ID: m.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}).Validate(b.TenantID) != nil || m.PolicyVersion == 0 || m.FactorVersion == 0 {
		return false
	}
	if allowUngenerated && ungeneratedMFAContinuation(m) {
		return i == nil && p.CommandCounters == nil
	}
	if _, err := identity.ParseCommandID(string(m.ID)); err != nil {
		return false
	}
	if m.ScopeDigest == ([32]byte{}) || !postgresExactTime(m.IssuedAt) || !postgresExactTime(m.ExpiresAt) || m.IssuedAt.Nanosecond() != 0 || m.ExpiresAt.Nanosecond() != 0 || m.IssuedAt.Unix() <= 0 || !m.ExpiresAt.After(m.IssuedAt) || m.ExpiresAt.Sub(m.IssuedAt) > 5*time.Minute {
		return false
	}
	if i == nil {
		return true
	}
	return validCapabilityIssuancePlan(i) && len(i.Grants) == 1 && i.RegistrationUserID == "" && i.ResetRecipientUserID == "" && i.MagicLinkRecipientUserID == "" && i.MFAContinuationUserID == m.UserID && i.Grants[0].Purpose == "identity.mfa.complete" && i.Grants[0].CapabilityID == string(m.ID) && i.Grants[0].ExpiresAt.Equal(m.ExpiresAt) && p.Contributors[len(p.Contributors)-1] == i.Contributor
}

// This is another closed profile of the same command journal, not a new
// authority or replay store. Its password owner must authenticate original
// comparison/browser custody and bound the child by original primary expiry.
// Unlike magic-link consumption it has no primary capability participant.
func encodePasswordMFAPlanMode(b identity.CommandBinding, fp [32]byte, p CommandPlan, allowUngenerated bool) ([]byte, error) {
	return encodePrimaryMFAPlanMode(b, fp, p, "password", allowUngenerated)
}

// Both non-consuming primary owners use the same bounded envelope grammar.
// The origin discriminator and domain-separated profile remain mandatory, so
// reuse preserves password's historical bytes without relabeling email proof.
func encodePrimaryMFAPlanMode(b identity.CommandBinding, fp [32]byte, p CommandPlan, origin string, allowUngenerated bool) ([]byte, error) {
	if !validPrimaryMFAPlanMode(b, p, origin, allowUngenerated) {
		return nil, invalidPlan()
	}
	for _, a := range p.Audits {
		if a.RetentionClass != "protected" {
			return nil, invalidPlan()
		}
	}
	base := p
	base.MFAContinuation = nil
	profile := "identity-" + origin + "-mfa-preparation-v1"
	if ungeneratedMFAContinuation(p.MFAContinuation) {
		profile = "identity-" + origin + "-mfa-ungenerated-v1"
	}
	if p.CapabilityIssuance != nil {
		profile = "identity-" + origin + "-mfa-challenge-v1"
	}
	var wire []byte
	var err error
	if p.CapabilityIssuance == nil {
		wire, err = encodeFeaturePlanMode(b, fp, base, true)
	} else {
		wire, err = encodeMagicLinkMFAIssuedBase(b, fp, base)
	}
	if err != nil {
		return nil, err
	}
	m := p.MFAContinuation
	issued, expires := uint64(m.IssuedAt.Unix()), uint64(m.ExpiresAt.Unix())
	if ungeneratedMFAContinuation(m) {
		issued, expires = 0, 0
	}
	out := cborMap(map[string][]byte{
		"base": cborBytes(wire), "origin": cborText(origin), "profile": cborText(profile), "version": cborUint(1),
		"challenge": cborMap(map[string][]byte{"id": cborText(string(m.ID)), "user_id": cborText(string(m.UserID)), "scope_digest": cborBytes(m.ScopeDigest[:]), "policy_version": cborUint(m.PolicyVersion), "factor_version": cborUint(m.FactorVersion), "issued_at": cborUint(issued), "expires_at": cborUint(expires)}),
	})
	if len(out) > 65536 {
		return nil, invalidPlan()
	}
	return out, nil
}

func decodePasswordMFAPlanMode(b identity.CommandBinding, fp [32]byte, data []byte, allowUngenerated bool) (CommandPlan, error) {
	return decodePrimaryMFAPlanMode(b, fp, data, "password", allowUngenerated)
}

func decodePrimaryMFAPlanMode(b identity.CommandBinding, fp [32]byte, data []byte, origin string, allowUngenerated bool) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 5)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != 0xa4 && r.data[0] != 0xa8 && r.data[0] != 0xa9 {
		return fail()
	}
	var p CommandPlan
	var err error
	profile := "identity-" + origin + "-mfa-preparation-v1"
	if r.data[0] == 0xa4 {
		profile = "identity-" + origin + "-mfa-challenge-v1"
		decodeBase := func(b identity.CommandBinding, fp [32]byte, wire []byte) (CommandPlan, error) {
			if len(wire) == 0 || wire[0] != 0xa8 && wire[0] != 0xa9 {
				return fail()
			}
			return decodeFeaturePlanMode(b, fp, wire, true)
		}
		p, err = decodeIssuanceWrappedPlan(b, fp, r.data[:int(n)], decodeBase, encodeMagicLinkMFAIssuedBase)
	} else {
		p, err = decodeFeaturePlanMode(b, fp, r.data[:int(n)], true)
	}
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("origin")
	r.consume(cborText(origin))
	r.key("profile")
	actual := r.string(128)
	ungenerated := allowUngenerated && p.CapabilityIssuance == nil && actual == "identity-"+origin+"-mfa-ungenerated-v1"
	if actual != profile && !ungenerated {
		return fail()
	}
	r.key("version")
	r.consume(cborUint(1))
	r.key("challenge")
	r.expect(5, 7)
	m := &MFAContinuationPlan{}
	r.key("id")
	m.ID = identity.CommandID(r.string(22))
	r.key("user_id")
	m.UserID = identity.UserID(r.string(128))
	r.key("issued_at")
	m.IssuedAt = time.Unix(int64(r.number(253402300799)), 0).UTC()
	r.key("expires_at")
	m.ExpiresAt = time.Unix(int64(r.number(253402300799)), 0).UTC()
	if ungenerated && m.IssuedAt.Unix() == 0 && m.ExpiresAt.Unix() == 0 {
		m.IssuedAt, m.ExpiresAt = time.Time{}, time.Time{}
	}
	r.key("scope_digest")
	r.digest(&m.ScopeDigest)
	r.key("factor_version")
	m.FactorVersion = r.number(math.MaxUint64)
	r.key("policy_version")
	m.PolicyVersion = r.number(math.MaxUint64)
	if !r.ok || len(r.data) != 0 {
		return fail()
	}
	p.MFAContinuation = m
	canonical, err := encodePrimaryMFAPlanMode(b, fp, p, origin, allowUngenerated)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	p.Digest = sha256.Sum256(data)
	return p, nil
}
