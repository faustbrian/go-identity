package postgres

import (
	"fmt"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

// CapabilityPlan freezes one signed, single-use capability's participant input.
// Purpose must match the command operation exactly. CapabilityID, ExpiresAt and
// MaxUses are the signed consumption identity; MaxUses must be one. ExpiresAt
// is a positive whole-second UTC instant within PostgreSQL years 1..9999.
// ReplayDigest is the participant's independently keyed, domain-separated replay
// lookup, not Reference.Digest or raw bearer bytes; ReplayKeyVersion selects its
// retained key. ProofFingerprint binds the validated immutable proof envelope.
// Digests and key version must be nonzero. The enclosing command fingerprint
// separately binds target identities and expected authority versions.
//
// This is declaration metadata, never cryptographic validation, freshness or
// transaction authority. The current Coordinator can reserve identifier intent
// through the typed contributor, but cannot Begin domain execution until the
// remaining participant phases exist. Do not mutate caller-owned
// inputs concurrently with digest preparation. Diagnostics are redacted and
// serialization is rejected; historical plans use the private canonical codec.
type CapabilityPlan struct {
	CapabilityID     string
	Purpose          capability.Purpose
	ReplayDigest     [32]byte
	ReplayKeyVersion uint32
	ProofFingerprint [32]byte
	ExpiresAt        time.Time
	MaxUses          uint32
}

// Format hides retained proof and replay metadata for every formatting verb.
func (CapabilityPlan) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CapabilityPlan(redacted)"))
}

// MarshalJSON prevents accidental export of retained proof metadata.
func (CapabilityPlan) MarshalJSON() ([]byte, error) { return nil, invalidPlan() }

func validateCapabilityPlan(binding identity.CommandBinding, plan *CapabilityPlan) error {
	if plan == nil {
		return nil
	}
	mfa := mfaCompletionPurpose(binding.OperationID) && plan.Purpose == "identity.mfa.complete"
	if plan.MaxUses != 1 || plan.ReplayKeyVersion == 0 || plan.ProofFingerprint == ([32]byte{}) || !mfa && plan.Purpose != capability.Purpose(binding.OperationID) || !postgresExactTime(plan.ExpiresAt) {
		return invalidPlan()
	}
	switch binding.OperationID {
	case "identity.identifier.attach", "identity.identifier.verify", "identity.identifier.make-primary", "identity.identifier.replace", "identity.identifier.remove", "identity.account.link-token", "identity.account.unlink", "identity.password.reset-complete", "identity.phone.password-reset-complete", "identity.magic-link.consume", "identity.organization.invitation.accept", "identity.anonymous.upgrade":
	default:
		if !mfa {
			return invalidPlan()
		}
	}
	if _, err := capability.NewReference(plan.CapabilityID, plan.Purpose, plan.ReplayDigest, plan.ExpiresAt); err != nil {
		return invalidPlan()
	}
	return nil
}

func encodeCapabilityPlan(p *CapabilityPlan) []byte {
	return cborMap(map[string][]byte{
		"capability_id":      cborText(p.CapabilityID),
		"purpose":            cborText(string(p.Purpose)),
		"replay_digest":      cborBytes(p.ReplayDigest[:]),
		"replay_key_version": cborUint(uint64(p.ReplayKeyVersion)),
		"proof_fingerprint":  cborBytes(p.ProofFingerprint[:]),
		"expires_at":         cborUint(uint64(p.ExpiresAt.Unix())),
		"max_uses":           cborUint(uint64(p.MaxUses)),
	})
}
