package postgres

import (
	"fmt"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// CaptchaEvidencePlan freezes token-free signed consuming custody separately
// from CAPTCHA issuance replay ownership. OriginalSignature commits to the full
// original signed flow/configuration carried by the immutable native command.
// Its authoritative command fingerprint must also cover every target/version
// field. PolicyVersion belongs to risk, not the command's authorization policy.
// This scalar declaration proves neither authenticity nor durable state. The
// native risk owner must authenticate it and perform all one-use phases inside
// the sole coordinator. Execution remains closed until those phases exist.
// Copies own their scalars; callers must not mutate input during preparation.
type CaptchaEvidencePlan struct {
	IssuanceCommandID                            string
	KeyVersion                                   uint32
	PolicyVersion                                uint64
	OriginalSignature, EvidenceDigest, Signature [32]byte
	IssuedAt, CheckedAt, ExpiresAt               time.Time
}

// Format hides private issuance/consumer linkage for every format verb.
func (CaptchaEvidencePlan) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CaptchaEvidencePlan(redacted)"))
}

// MarshalJSON rejects private signed custody serialization.
func (CaptchaEvidencePlan) MarshalJSON() ([]byte, error) { return nil, invalidPlan() }

// MarshalText rejects private signed custody serialization.
func (CaptchaEvidencePlan) MarshalText() ([]byte, error) { return nil, invalidPlan() }

func validateCaptchaEvidencePlan(b identity.CommandBinding, p CommandPlan) error {
	c := p.CaptchaEvidence
	if c == nil {
		return nil
	}
	if p.Feature == nil || p.SubjectType == "" || p.CaptchaReplayReservation || captchaReplayOperation(p.Feature.Operation) || c.IssuanceCommandID == string(b.CommandID) || c.KeyVersion == 0 || c.PolicyVersion == 0 || c.OriginalSignature == ([32]byte{}) || c.EvidenceDigest == ([32]byte{}) || c.Signature == ([32]byte{}) || !validRiskTime(c.IssuedAt, true) || !validRiskTime(c.CheckedAt, false) || !validRiskTime(c.ExpiresAt, true) || c.CheckedAt.Before(c.IssuedAt) || !c.CheckedAt.Before(c.ExpiresAt) || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > 2*time.Minute {
		return invalidPlan()
	}
	if _, err := identity.ParseCommandID(c.IssuanceCommandID); err != nil {
		return invalidPlan()
	}
	if p.RiskEvidence != nil && c.PolicyVersion != p.RiskEvidence.PolicyVersion || p.CommandCounters != nil && c.PolicyVersion != p.CommandCounters.PolicyVersion {
		return invalidPlan()
	}
	return nil
}

func cloneCaptchaEvidencePlan(p *CaptchaEvidencePlan) *CaptchaEvidencePlan {
	if p == nil {
		return nil
	}
	copy := *p
	return &copy
}

func encodeCaptchaEvidencePlan(p *CaptchaEvidencePlan) []byte {
	return cborMap(map[string][]byte{
		"issuance_command_id": cborText(p.IssuanceCommandID),
		"key_version":         cborUint(uint64(p.KeyVersion)), "policy_version": cborUint(p.PolicyVersion),
		"original_signature": cborBytes(p.OriginalSignature[:]), "evidence_digest": cborBytes(p.EvidenceDigest[:]), "signature": cborBytes(p.Signature[:]),
		"issued_at": cborText(p.IssuedAt.Format(time.RFC3339Nano)), "checked_at": cborText(p.CheckedAt.Format(time.RFC3339Nano)), "expires_at": cborText(p.ExpiresAt.Format(time.RFC3339Nano)),
	})
}

func readCaptchaEvidencePlan(r *planReader) *CaptchaEvidencePlan {
	p := &CaptchaEvidencePlan{}
	r.expect(5, 9)
	for range 9 {
		switch r.string(32) {
		case "issuance_command_id":
			p.IssuanceCommandID = r.string(22)
		case "key_version":
			p.KeyVersion = uint32(r.number(math.MaxUint32))
		case "policy_version":
			p.PolicyVersion = r.number(math.MaxUint64)
		case "original_signature":
			r.digest(&p.OriginalSignature)
		case "evidence_digest":
			r.digest(&p.EvidenceDigest)
		case "signature":
			r.digest(&p.Signature)
		case "issued_at":
			p.IssuedAt = readRiskTime(r)
		case "checked_at":
			p.CheckedAt = readRiskTime(r)
		case "expires_at":
			p.ExpiresAt = readRiskTime(r)
		default:
			r.ok = false
			return p
		}
	}
	return p
}
