package risk

import (
	"context"
	"fmt"
)

// VelocityNativeConfirmation is the configured native owner's acknowledgement
// of the exact published-to-confirmed marker transition. It retains the original
// primary confirmation chain, not current primary eligibility or surviving
// counters. Zero is invalid; copies are immutable and concurrent-safe. It cannot
// issue authority or be serialized. Only owned adapter composition may retain it.
type VelocityNativeConfirmation struct{ acknowledgement *velocityNativeConfirmation }
type velocityNativeConfirmation struct {
	issuer       *velocityNativeAuthority
	confirmation *velocityConfirmation
}

// AcknowledgeNativeConfirmation must be called by the concrete native owner
// only after attributable exact-marker confirmation IO and continuity checks.
// It rechecks the original primary lease, covered cut and recorded confirmation
// under ctx before exposing acknowledgement. Lost/late IO grants none and must
// never be resent implicitly. This primitive does not perform IO or certify a
// malicious configurator. Trusted composition must not expose the issuer.
func (i VelocityNativeIssuer) AcknowledgeNativeConfirmation(ctx context.Context, l VelocityLease, c VelocityClosure, p VelocityPublication, k VelocityConfirmation) (VelocityNativeConfirmation, error) {
	if i.native == nil {
		return VelocityNativeConfirmation{}, ErrInvalidVelocityRecovery
	}
	if _, err := (VelocityNativeVerifier{nativeVerifier: i.native}).Confirmation(ctx, l, c, p, k); err != nil {
		return VelocityNativeConfirmation{}, err
	}
	return VelocityNativeConfirmation{acknowledgement: &velocityNativeConfirmation{issuer: i.native, confirmation: k.confirmation}}, nil
}

// NativeConfirmation returns copied historical cut facts only when every
// supplied receipt is the exact original configured acknowledgement chain.
// Unlike Confirmation, this pure identity read does not invoke recovery-only
// checkers: an authoritative healthy transition necessarily invalidates those
// replaying checkers. The primary must independently authenticate persisted
// scope, generation, owner, cut, confirmation and original expiry under its
// locks before transitioning or reconciling state. Native continuity must still
// be checked at every effect boundary. Success here is never healthy admission,
// freshness, permission to resend IO or proof that the primary is available.
func (v VelocityNativeVerifier) NativeConfirmation(l VelocityLease, c VelocityClosure, p VelocityPublication, k VelocityConfirmation, a VelocityNativeConfirmation) (VelocityClosureBinding, error) {
	if v.nativeVerifier == nil || a.acknowledgement == nil || a.acknowledgement.issuer != v.nativeVerifier || k.confirmation == nil || a.acknowledgement.confirmation != k.confirmation || p.state == nil || k.confirmation.publication != p.state || p.state.issuer != v.nativeVerifier || c.state == nil || p.state.closure != c.state || l.state == nil || c.state.lease != l.state || l.state.issuer != v.nativeVerifier.journal {
		return VelocityClosureBinding{}, ErrInvalidVelocityRecovery
	}
	return c.state.binding, nil
}

func (VelocityNativeConfirmation) Format(s fmt.State, _ rune) { velocityRedacted(s) }
func (VelocityNativeConfirmation) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
func (VelocityNativeConfirmation) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
