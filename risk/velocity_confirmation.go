package risk

import (
	"context"
	"fmt"
)

// VelocityConfirmation is immutable primary-issued custody of one recorded
// publication confirmation. It binds the exact original publication, closure
// and lease, not merely equal projected facts. Zero is invalid. Copies are safe
// for concurrent reads; formatting is redacted and serialization is forbidden.
// It proves neither present native continuity nor permission to admit traffic.
type VelocityConfirmation struct{ confirmation *velocityConfirmation }
type velocityConfirmation struct {
	publication *velocityPublication
	check       func(context.Context) error
}

// AcknowledgeConfirmation records an already durably acknowledged primary
// confirmation of the exact configured native publication. The concrete primary
// owner supplies a concurrent-safe, context-bounded checker of its persisted
// confirmation and original expiry. It must not substitute a covered-cut check,
// renew timestamps or hold SQL locks across native IO. This method checks current
// original lease, covered cut and confirmation before exposing custody, but
// performs no storage mutation itself. Failed or ambiguous primary commits must
// not call it until the same exact command has authoritatively reconciled.
// Cancellation/deadlines survive; other authority errors are redacted unavailable.
func (i VelocityJournalIssuer) AcknowledgeConfirmation(ctx context.Context, l VelocityLease, c VelocityClosure, p VelocityPublication, check func(context.Context) error) (VelocityConfirmation, error) {
	if i.journal == nil || check == nil {
		return VelocityConfirmation{}, ErrInvalidVelocityRecovery
	}
	if _, err := (VelocityNativeVerifier{nativeVerifier: i.journal.native}).Publication(ctx, l, c, p); err != nil {
		return VelocityConfirmation{}, err
	}
	if err := checkVelocityAuthority(ctx, check); err != nil {
		return VelocityConfirmation{}, err
	}
	return VelocityConfirmation{confirmation: &velocityConfirmation{publication: p.state, check: check}}, nil
}

// Confirmation verifies exact configured custody and independently rechecks
// the original primary lease, covered cut and persisted confirmation. Returned
// facts are copied without refreshing expiry or coverage. A separately issued
// publication with equal fields cannot replace the original acknowledgement.
// The retained recovery checks remain recovery-only: an eventual healthy-state
// admission contract must separately establish current primary eligibility and
// exact native continuity. This read performs no native IO or health transition.
func (v VelocityNativeVerifier) Confirmation(ctx context.Context, l VelocityLease, c VelocityClosure, p VelocityPublication, k VelocityConfirmation) (VelocityClosureBinding, error) {
	if k.confirmation == nil || p.state == nil || k.confirmation.publication != p.state {
		return VelocityClosureBinding{}, ErrInvalidVelocityRecovery
	}
	b, err := v.Publication(ctx, l, c, p)
	if err != nil {
		return VelocityClosureBinding{}, err
	}
	if err := checkVelocityAuthority(ctx, k.confirmation.check); err != nil {
		return VelocityClosureBinding{}, err
	}
	return b, nil
}

func (VelocityConfirmation) Format(s fmt.State, _ rune)   { velocityRedacted(s) }
func (VelocityConfirmation) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VelocityConfirmation) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
