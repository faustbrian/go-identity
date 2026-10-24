package postgres

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// MFAContinuationPlan declares a challenge-only result of admitting an original
// password/UV-passkey primary or consuming a magic-link proof. ScopeDigest binds immutable
// scope, including browser, primary proof, methods and remember policy. The child
// capability has this ID and expiry. Factor and policy versions must be fenced
// by their actual owners; this declaration proves neither MFA nor authentication.
// It cannot accompany signup or session creation. Times are UTC whole seconds,
// with a five-minute maximum and no extension beyond the original primary proof.
// Preparation alone may omit ID/digest/times together while fixing the selected
// user/policy/factor. The journal-owned generator supplies those original child
// fields once. Ordinary execution and history require the complete declaration;
// restoration preserves it and adds exactly one original-generation child.
type MFAContinuationPlan struct {
	ID            identity.CommandID
	UserID        identity.UserID
	ScopeDigest   [32]byte
	PolicyVersion uint64
	FactorVersion uint64
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// Format hides subject and retained scope metadata from diagnostics.
func (MFAContinuationPlan) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFAContinuationPlan(redacted)"))
}

// MarshalJSON forbids exporting retained scope through general serialization.
// The coordinator's private canonical codec owns historical representation.
func (MFAContinuationPlan) MarshalJSON() ([]byte, error) { return nil, invalidPlan() }

func cloneMFAContinuationPlan(p *MFAContinuationPlan) *MFAContinuationPlan {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}

func validMagicLinkMFAPlan(b identity.CommandBinding, p CommandPlan) bool {
	return validMagicLinkMFAPlanMode(b, p, false)
}

func ungeneratedMFAContinuation(m *MFAContinuationPlan) bool {
	return m != nil && m.ID == "" && m.ScopeDigest == ([32]byte{}) && m.IssuedAt.IsZero() && m.ExpiresAt.IsZero()
}

func validMagicLinkMFAPlanMode(b identity.CommandBinding, p CommandPlan, allowUngenerated bool) bool {
	m, i := p.MFAContinuation, p.CapabilityIssuance
	if m == nil || p.Feature == nil || p.Feature.Operation != magicLinkConsumeOperation() || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}) || b.UserID != "" || b.AnonymousFlowID == "" || p.SubjectType != "authentication_attempt" || p.MagicLinkRegistration != nil || p.MagicLinkRequestAcceptance || p.SignupAcceptance || p.Delivery != nil || p.RiskEvidence != nil || p.OTP != nil || p.CaptchaEvidence != nil || p.CaptchaReplayReservation || p.Capability == nil || validateCapabilityPlan(b, p.Capability) != nil || p.Lifecycle == nil || p.Lifecycle.EventType != "mfa.challenge.created.v1" || p.Lifecycle.BeforeVersion != 0 || p.Lifecycle.AfterVersion != 0 || len(p.Contributors) == 0 {
		return false
	}
	oneUse := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	if allowUngenerated && ungeneratedMFAContinuation(m) {
		return i == nil && p.CommandCounters == nil && (identity.User{ID: m.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}).Validate(b.TenantID) == nil && m.PolicyVersion > 0 && m.FactorVersion > 0 && p.Contributors[len(p.Contributors)-1] == oneUse
	}
	if _, err := identity.ParseCommandID(string(m.ID)); err != nil {
		return false
	}
	if (identity.User{ID: m.UserID, TenantID: b.TenantID, Status: identity.StatusActive, Version: 1}).Validate(b.TenantID) != nil || m.ScopeDigest == ([32]byte{}) || m.PolicyVersion == 0 || m.FactorVersion == 0 || !postgresExactTime(m.IssuedAt) || !postgresExactTime(m.ExpiresAt) || m.IssuedAt.Nanosecond() != 0 || m.ExpiresAt.Nanosecond() != 0 || m.IssuedAt.Unix() <= 0 || !m.ExpiresAt.After(m.IssuedAt) || m.ExpiresAt.Sub(m.IssuedAt) > 5*time.Minute || m.ExpiresAt.After(p.Capability.ExpiresAt) {
		return false
	}
	if i == nil {
		return p.Contributors[len(p.Contributors)-1] == oneUse
	}
	if !validCapabilityIssuancePlan(i) || len(i.Grants) != 1 || i.RegistrationUserID != "" || i.ResetRecipientUserID != "" || i.MagicLinkRecipientUserID != "" || i.MFAContinuationUserID != m.UserID || len(p.Contributors) < 2 {
		return false
	}
	g := i.Grants[0]
	return g.Purpose == "identity.mfa.complete" && g.CapabilityID == string(m.ID) && g.CapabilityID != p.Capability.CapabilityID && g.ProofFingerprint != p.Capability.ProofFingerprint && (g.ReplayKeyVersion != p.Capability.ReplayKeyVersion || g.ReplayDigest != p.Capability.ReplayDigest) && g.ExpiresAt.Equal(m.ExpiresAt) && p.Contributors[len(p.Contributors)-2] == (ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}) && p.Contributors[len(p.Contributors)-1] == i.Contributor
}

// The fixed-depth inner envelope reuses the original issuance grammar. Its
// private proof-free base cannot be admitted independently. Only the outer
// envelope binds both original primary consumption and challenge-only issuance.
func encodeMagicLinkMFAIssuedBase(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	encodeBase := func(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
		if p.CapabilityIssuance != nil || p.MFAContinuation != nil || p.Capability != nil {
			return nil, invalidPlan()
		}
		return encodeFeaturePlanMode(b, fp, p, true)
	}
	return encodeIssuanceWrappedPlan(b, fp, p, encodeBase)
}

func encodeMagicLinkMFAPlan(b identity.CommandBinding, fp [32]byte, p CommandPlan) ([]byte, error) {
	return encodeMagicLinkMFAPlanMode(b, fp, p, false)
}

func encodeMagicLinkMFAPlanMode(b identity.CommandBinding, fp [32]byte, p CommandPlan, allowUngenerated bool) ([]byte, error) {
	if !validMagicLinkMFAPlanMode(b, p, allowUngenerated) {
		return nil, invalidPlan()
	}
	for _, a := range p.Audits {
		if a.RetentionClass != "protected" {
			return nil, invalidPlan()
		}
	}
	base := p
	base.MFAContinuation, base.Capability = nil, nil
	parentIndex := len(p.Contributors) - 1
	profile := "identity-magic-link-mfa-preparation-v1"
	var wire []byte
	var err error
	if p.CapabilityIssuance == nil {
		if ungeneratedMFAContinuation(p.MFAContinuation) {
			profile = "identity-magic-link-mfa-ungenerated-v1"
		}
		base.Contributors = p.Contributors[:parentIndex]
		wire, err = encodeFeaturePlanMode(b, fp, base, true)
	} else {
		parentIndex--
		profile = "identity-magic-link-mfa-challenge-v1"
		base.Contributors = append(append([]ContributorDescriptor(nil), p.Contributors[:parentIndex]...), p.CapabilityIssuance.Contributor)
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
	owner := p.Contributors[parentIndex]
	result := cborMap(map[string][]byte{
		"base": cborBytes(wire), "profile": cborText(profile), "version": cborUint(1),
		"challenge": cborMap(map[string][]byte{
			"id": cborText(string(m.ID)), "user_id": cborText(string(m.UserID)), "scope_digest": cborBytes(m.ScopeDigest[:]),
			"policy_version": cborUint(m.PolicyVersion), "factor_version": cborUint(m.FactorVersion),
			"issued_at": cborUint(issued), "expires_at": cborUint(expires),
		}),
		"capability":  encodeCapabilityPlan(p.Capability),
		"contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))}),
	})
	if len(result) > 65536 {
		return nil, invalidPlan()
	}
	return result, nil
}

func decodeMagicLinkMFAPlan(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
	return decodeMagicLinkMFAPlanMode(b, fp, data, false)
}

func decodeMagicLinkMFAPlanMode(b identity.CommandBinding, fp [32]byte, data []byte, allowUngenerated bool) (CommandPlan, error) {
	fail := func() (CommandPlan, error) { return CommandPlan{}, identity.UnavailableError{} }
	if len(data) == 0 || len(data) > 65536 {
		return fail()
	}
	r := planReader{attributeReader: attributeReader{data: data}, ok: true}
	r.expect(5, 6)
	r.key("base")
	n, ok := r.head(2)
	if !r.ok || !ok || n == 0 || n > uint64(len(r.data)) || r.data[0] != 0xa4 && r.data[0] != 0xa8 && r.data[0] != 0xa9 {
		return fail()
	}
	decodeBase := func(b identity.CommandBinding, fp [32]byte, data []byte) (CommandPlan, error) {
		if len(data) == 0 || data[0] != 0xa8 && data[0] != 0xa9 {
			return fail()
		}
		return decodeFeaturePlanMode(b, fp, data, true)
	}
	profile := "identity-magic-link-mfa-preparation-v1"
	var p CommandPlan
	var err error
	if r.data[0] == 0xa4 {
		profile = "identity-magic-link-mfa-challenge-v1"
		p, err = decodeIssuanceWrappedPlan(b, fp, r.data[:int(n)], decodeBase, encodeMagicLinkMFAIssuedBase)
	} else {
		p, err = decodeBase(b, fp, r.data[:int(n)])
	}
	if err != nil {
		return fail()
	}
	r.data = r.data[int(n):]
	r.key("profile")
	actualProfile := r.string(128)
	ungenerated := allowUngenerated && p.CapabilityIssuance == nil && actualProfile == "identity-magic-link-mfa-ungenerated-v1"
	if actualProfile != profile && !ungenerated {
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
	r.key("capability")
	r.expect(5, 7)
	v := &CapabilityPlan{}
	r.key("purpose")
	r.consume(cborText("identity.magic-link.consume"))
	v.Purpose = "identity.magic-link.consume"
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
	if !r.ok || len(r.data) != 0 || len(p.Contributors) == 0 {
		return fail()
	}
	p.MFAContinuation, p.Capability = m, v
	if p.CapabilityIssuance == nil {
		p.Contributors = append(p.Contributors, owner)
	} else {
		issuer := p.Contributors[len(p.Contributors)-1]
		p.Contributors = append(p.Contributors[:len(p.Contributors)-1], owner, issuer)
	}
	canonical, err := encodeMagicLinkMFAPlanMode(b, fp, p, allowUngenerated)
	if err != nil || !bytes.Equal(canonical, data) {
		return fail()
	}
	p.Digest = sha256.Sum256(data)
	return p, nil
}
