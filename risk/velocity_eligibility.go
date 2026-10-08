package risk

import (
	"context"
	"fmt"
)

// VelocityEligibility retains primary-issued custody of the exact activated
// recovery chain with a current-primary checker. It is not a cached allowance,
// native continuity proof or effect permit. Only trusted owned composition may
// retain it. Zero is invalid; copies are immutable/concurrent-safe, formatting
// is redacted and serialization is forbidden. Original expiry is never renewed.
type VelocityEligibility struct{ eligibility *velocityEligibility }
type velocityEligibility struct {
	native *velocityNativeConfirmation
	check  func(context.Context) error
}

// AcknowledgeEligibility records an already acknowledged primary activation of
// the exact original native-confirmed chain. The concrete primary owner must
// supply its concurrent-safe, context-bounded current healthy-state checker,
// including the original expiry, rather than a replay or caller health assertion.
// Pure historical identity validation intentionally invokes no replay callbacks:
// the primary healthy transition invalidates those callbacks. This method does
// not activate storage, renew time, observe native state or grant debit authority.
// Failed/ambiguous activation grants none until exact primary reconciliation.
// Trusted composition must keep this issuer private and end all SQL transactions
// before native IO. Cancellation/deadlines survive; other failures are redacted.
func (i VelocityJournalIssuer) AcknowledgeEligibility(ctx context.Context, l VelocityLease, c VelocityClosure, p VelocityPublication, k VelocityConfirmation, a VelocityNativeConfirmation, check func(context.Context) error) (VelocityEligibility, error) {
	if i.journal == nil || check == nil {
		return VelocityEligibility{}, ErrInvalidVelocityRecovery
	}
	if _, err := (VelocityNativeVerifier{nativeVerifier: i.journal.native}).NativeConfirmation(l, c, p, k, a); err != nil {
		return VelocityEligibility{}, err
	}
	if err := checkVelocityAuthority(ctx, check); err != nil {
		return VelocityEligibility{}, err
	}
	return VelocityEligibility{eligibility: &velocityEligibility{native: a.acknowledgement, check: check}}, nil
}

// Eligibility authenticates the exact configured activated chain and rechecks
// current primary eligibility before returning unchanged copied cut facts.
// It does not invoke replay-only callbacks, refresh expiry, inspect native
// continuity, mutate storage or authorize implicit retry. A distinct receipt
// with equal fields cannot replace the original chain. The concrete native
// owner still must enforce its exact marker and continuity at the atomic effect
// boundary; the journal owner must preserve intent/result conservation.
func (v VelocityNativeVerifier) Eligibility(ctx context.Context, l VelocityLease, c VelocityClosure, p VelocityPublication, k VelocityConfirmation, a VelocityNativeConfirmation, h VelocityEligibility) (VelocityClosureBinding, error) {
	if h.eligibility == nil || a.acknowledgement == nil || h.eligibility.native != a.acknowledgement {
		return VelocityClosureBinding{}, ErrInvalidVelocityRecovery
	}
	b, err := v.NativeConfirmation(l, c, p, k, a)
	if err != nil {
		return VelocityClosureBinding{}, err
	}
	if err := checkVelocityAuthority(ctx, h.eligibility.check); err != nil {
		return VelocityClosureBinding{}, err
	}
	return b, nil
}

func (VelocityEligibility) Format(s fmt.State, _ rune)   { velocityRedacted(s) }
func (VelocityEligibility) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (VelocityEligibility) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
