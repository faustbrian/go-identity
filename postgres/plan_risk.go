package postgres

import (
	"fmt"
	"math"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// RiskEvidencePlan is the consumer-owned scalar projection of risk's signed
// PreparedEvidenceUse. Issuance identity and consuming command identity remain
// separate; digests bind the omitted raw recovery/configuration/bearer scope.
// IssuedAt and ExpiresAt are original UTC microsecond instants; CheckedAt is
// the original UTC precheck instant, possibly nanosecond precision. Nothing
// here renews freshness or proves cryptographic authenticity or row existence.
// The registered risk adapter must authenticate every scalar, match current
// policy and native command scope, and reserve the existing authoritative row.
// Reset initiation and the closed completion conjunction are admitted; the
// latter requires separate capability, consuming OTP and completion-risk
// participants. Copies own their scalars. Diagnostics and serialization are redacted.
type RiskEvidencePlan struct {
	IssuanceCommandID, Tenant, Subject, IssuerActor string
	Purpose, Phase, RecoveryOperation               string
	PolicyVersion                                   uint64
	KeyVersion                                      uint32
	IntentDigest                                    [32]byte
	ConsumerCommandID, ConsumerActor                string
	EvidenceDigest, ProofDigest, Signature          [32]byte
	IssuedAt, CheckedAt, ExpiresAt                  time.Time
}

func (RiskEvidencePlan) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RiskEvidencePlan(redacted)"))
}
func (RiskEvidencePlan) MarshalJSON() ([]byte, error) { return nil, invalidPlan() }
func (RiskEvidencePlan) MarshalText() ([]byte, error) { return nil, invalidPlan() }

func riskInitiationOperation(op identity.FeatureOperation) bool {
	// A public request schema or an arbitrary schema with the same operation ID
	// must not accidentally activate the native one-time preparation protocol.
	return op == (identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-request", SchemaID: "identity.phone.password-reset-request.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired})
}

func validRiskTime(t time.Time, microseconds bool) bool {
	return !t.IsZero() && t.Location() == time.UTC && t.Year() >= 1 && t.Year() <= 9999 && (!microseconds || t.Nanosecond()%1000 == 0)
}

func validateRiskPlan(b identity.CommandBinding, p CommandPlan) error {
	r := p.RiskEvidence
	if r == nil {
		return nil
	}
	initiation := p.Feature != nil && riskInitiationOperation(p.Feature.Operation) && p.SubjectType == "phone" && p.Capability == nil && r.Phase == "phone-reset-initiation" && r.Purpose == "phone-password-reset-initiate"
	// The capability wrapper strips only its own proof while encoding its
	// fixed-depth base. Full phone completion still requires that wrapper, the
	// exact SMS attempt and the distinct completion evidence before admission.
	completion := p.Feature != nil && p.Feature.Operation == phonePasswordResetOperation() && p.SubjectType == "credential" && p.OTP != nil && p.OTP.Mode == OTPConsume && r.Phase == "phone-reset-completion" && r.Purpose == "phone-password-reset-complete"
	if !initiation && !completion || r.RecoveryOperation != b.OperationID || r.Tenant != string(b.TenantID) || r.Subject != string(b.UserID) || r.ConsumerCommandID != string(b.CommandID) || r.ConsumerActor != string(b.ActorID) || r.IssuanceCommandID == r.ConsumerCommandID || !boundedRiskScope(r.IssuerActor) || r.PolicyVersion == 0 || r.KeyVersion == 0 || r.IntentDigest == ([32]byte{}) || r.EvidenceDigest == ([32]byte{}) || r.ProofDigest == ([32]byte{}) || r.Signature == ([32]byte{}) || !validRiskTime(r.IssuedAt, true) || !validRiskTime(r.CheckedAt, false) || !validRiskTime(r.ExpiresAt, true) || !r.ExpiresAt.After(r.IssuedAt) || r.ExpiresAt.Sub(r.IssuedAt) > 2*time.Minute || r.CheckedAt.Before(r.IssuedAt) || !r.CheckedAt.Before(r.ExpiresAt) {
		return invalidPlan()
	}
	if _, err := identity.ParseCommandID(r.IssuanceCommandID); err != nil {
		return invalidPlan()
	}
	return nil
}

func boundedRiskScope(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, b := range []byte(s) {
		if b < 33 || b > 126 {
			return false
		}
	}
	return true
}

func encodeRiskPlan(p *RiskEvidencePlan) []byte {
	return cborMap(map[string][]byte{
		"issuance_command_id": cborText(p.IssuanceCommandID), "tenant": cborText(p.Tenant), "subject": cborText(p.Subject), "issuer_actor": cborText(p.IssuerActor),
		"purpose": cborText(p.Purpose), "phase": cborText(p.Phase), "recovery_operation": cborText(p.RecoveryOperation), "policy_version": cborUint(p.PolicyVersion), "key_version": cborUint(uint64(p.KeyVersion)), "intent_digest": cborBytes(p.IntentDigest[:]),
		"consumer_command_id": cborText(p.ConsumerCommandID), "consumer_actor": cborText(p.ConsumerActor), "evidence_digest": cborBytes(p.EvidenceDigest[:]), "proof_digest": cborBytes(p.ProofDigest[:]), "signature": cborBytes(p.Signature[:]),
		"issued_at": cborText(p.IssuedAt.Format(time.RFC3339Nano)), "checked_at": cborText(p.CheckedAt.Format(time.RFC3339Nano)), "expires_at": cborText(p.ExpiresAt.Format(time.RFC3339Nano)),
	})
}

func readRiskPlan(r *planReader) *RiskEvidencePlan {
	p := &RiskEvidencePlan{}
	r.expect(5, 18)
	for range 18 {
		switch r.string(32) {
		case "issuance_command_id":
			p.IssuanceCommandID = r.string(22)
		case "tenant":
			p.Tenant = r.string(128)
		case "subject":
			p.Subject = r.string(128)
		case "issuer_actor":
			p.IssuerActor = r.string(128)
		case "purpose":
			p.Purpose = r.string(128)
		case "phase":
			p.Phase = r.string(32)
		case "recovery_operation":
			p.RecoveryOperation = r.string(128)
		case "policy_version":
			p.PolicyVersion = r.number(math.MaxUint64)
		case "key_version":
			p.KeyVersion = uint32(r.number(math.MaxUint32))
		case "intent_digest":
			r.digest(&p.IntentDigest)
		case "consumer_command_id":
			p.ConsumerCommandID = r.string(22)
		case "consumer_actor":
			p.ConsumerActor = r.string(128)
		case "evidence_digest":
			r.digest(&p.EvidenceDigest)
		case "proof_digest":
			r.digest(&p.ProofDigest)
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

func readRiskTime(r *planReader) time.Time {
	t, err := time.Parse(time.RFC3339Nano, r.string(35))
	if err != nil {
		r.ok = false
	}
	return t
}
