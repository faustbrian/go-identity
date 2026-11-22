package identity

import (
	"time"

	"github.com/faustbrian/go-capability/v2"
)

// AccountUnlinkProofSpec is the trusted native issuer's unsigned input.
// Preparation must be the exact original typed unlink command. The builder
// checks its shape, not the authenticity or current authority of its password
// proof. Admit the original and select time from the original authority window
// before using the configured issuer.
type AccountUnlinkProofSpec struct {
	Preparation Command
	Issuer      string
	Audience    string
	ID          string
	IssuedAt    time.Time
	ExpiresAt   time.Time
}

// BuildAccountUnlinkProofPayload creates the canonical one-use, non-bearer
// payload for the original unlink. Issue and expiry use whole seconds and must
// fit within the original password proof interval, with exclusive expiry.
// It neither signs nor exposes the original session credential and does not
// establish current permission to issue. The returned payload is caller-owned
// sensitive intent. Invalid input returns a zero payload and redacted error.
func BuildAccountUnlinkProofPayload(s AccountUnlinkProofSpec) (capability.Payload, error) {
	invalid := InvalidInputError{Field: "unlink_proof_spec"}
	original, _, ok := s.Preparation.AccountUnlinkPreparationInput()
	if !ok || !validClaimIssuer(s.Issuer) || len(s.Issuer) > 256 || !validDirectoryID(s.Audience) || !validDirectoryID(s.ID) {
		return capability.Payload{}, invalid
	}
	issued, expires := s.IssuedAt.UTC(), s.ExpiresAt.UTC()
	if issued.IsZero() || expires.IsZero() || issued.Year() < 1 || expires.Year() > 9999 ||
		issued.Nanosecond() != 0 || expires.Nanosecond() != 0 || !expires.After(issued) {
		return capability.Payload{}, invalid
	}
	parent := original.Primary.Proof
	if issued.Before(parent.IssuedAt) || expires.After(parent.ExpiresAt) {
		return capability.Payload{}, invalid
	}
	intent := AccountUnlinkCommand{
		Binding: original.Binding, Change: original.Change, SessionID: original.SessionID,
		SessionVersion: original.SessionVersion, RevokeProvider: original.RevokeProvider,
	}
	return capability.Payload{
		Version: 1, Issuer: s.Issuer, Audiences: []string{s.Audience}, ID: s.ID,
		Subject: string(intent.Binding.UserID), Tenant: string(intent.Binding.TenantID),
		Resource: string(intent.Change.AccountID), Operation: intent.Binding.OperationID,
		MaxUses: 1, IssuedAt: issued, NotBefore: issued, ExpiresAt: expires, Caveats: unlinkCaveats(intent),
	}, nil
}
