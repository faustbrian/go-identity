package email

import (
	"errors"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// ErrInvalidRemoval rejects invalid or unsafe removal proposals without
// exposing account/address existence, credentials or available recovery paths.
var ErrInvalidRemoval = errors.New("identity.email.invalid_removal")

// RemovalRecoveryPolicy selects the email recovery path conserved by removal.
// It is startup policy, not a caller-supplied claim of available recovery.
type RemovalRecoveryPolicy uint8

const (
	// PreserveVerifiedEmailRecovery requires at least one remaining verified
	// email. The native selected password/known-empty-MFA profile must additionally
	// fence its actual eligible password credential and factor authority.
	PreserveVerifiedEmailRecovery RemovalRecoveryPolicy = iota + 1
)

// RemovalProfile selects required session and recovery effects. Zero denies.
// Primary removal is permitted when another verified email remains: primary
// designation is not native password signin/reset eligibility. No replacement
// primary is silently selected and no authentication is issued.
type RemovalProfile struct {
	Sessions ChangeSessionPolicy
	Recovery RemovalRecoveryPolicy
}

// Validate rejects unselected/unknown policy without inferring weaker defaults.
func (p RemovalProfile) Validate() error {
	if p.Sessions != InvalidateIdentifierSessions || p.Recovery != PreserveVerifiedEmailRecovery {
		return ErrInvalidRemoval
	}
	return nil
}

// PlanRemoval computes the existing kernel's copied removal transition and
// denies losing the last verified email. It performs no IO, proof authentication,
// locks, credential/factor eligibility checks or consumption. Native composition
// must repeat it under the complete partition lock and atomically conserve
// credential/factor authority, exact-target token retirement, required session
// effects, reuse policy, audit and lifecycle. This proposal grants no permission.
// Existing address text, independent versions and verification times are never
// normalized or renewed. Inputs remain immutable; failures return zero mutation.
func (p RemovalProfile) PlanRemoval(before identity.IdentifierState, change identity.IdentifierChange, now time.Time) (identity.IdentifierMutation, error) {
	if p.Validate() != nil || change.Action != identity.IdentifierRemove {
		return identity.IdentifierMutation{}, ErrInvalidRemoval
	}
	mutation, err := identity.ApplyIdentifierChange(before, change, now)
	if err != nil {
		return identity.IdentifierMutation{}, err
	}
	if mutation.Retired == nil || mutation.Retired.Kind != identity.IdentifierEmail {
		return identity.IdentifierMutation{}, ErrInvalidRemoval
	}
	for _, a := range mutation.State.Identifiers {
		if a.Kind == identity.IdentifierEmail && a.Verified {
			return mutation, nil
		}
	}
	return identity.IdentifierMutation{}, ErrInvalidRemoval
}
