package postgres

import (
	"context"
	"crypto/hmac"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// OwnedEligibility exports acknowledged primary activation into the configured
// custody graph using this adapter's concrete CheckHealthy on every use. It
// accepts no caller-supplied checker, time, generation or health assertion.
// The original lease and native-confirmed cut must match the activated receipt.
// One journal timeout bounds the export; retained checks independently bound
// later reads without refreshing original expiry, cut or activation time.
// Export performs no native IO or writes, and all primary transactions end
// before native work. Native continuity, exact-marker enforcement and journaled
// intent/result execution remain separate requirements. Invalid custody returns
// InvalidInputError; primary failures return redacted UnavailableError, with
// cancellation/deadlines preserved. Failure exposes no eligibility.
func (r VelocityRecovery) OwnedEligibility(ctx context.Context, healthy VelocityHealthy, owned risk.VelocityLease, exported risk.VelocityClosure, publication risk.VelocityPublication, confirmation risk.VelocityConfirmation, native risk.VelocityNativeConfirmation) (risk.VelocityEligibility, error) {
	if r.state == nil || r.state.journalIssuer == (risk.VelocityJournalIssuer{}) || healthy.state == nil || healthy.state.owner != r.state || healthy.state.activated.IsZero() || healthy.state.lease == nil || healthy.state.cut == nil || healthy.state.cut.lease != healthy.state.lease {
		return risk.VelocityEligibility{}, identity.InvalidInputError{Field: "velocity_eligibility"}
	}
	s, h := r.state, healthy.state
	l := h.lease
	bounded, cancel, err := s.bounded(ctx)
	if err != nil {
		return risk.VelocityEligibility{}, err
	}
	defer cancel()
	lb, err := s.journalReader.Lease(owned)
	if err != nil || lb.Tenant != l.tenant || !hmac.Equal(lb.Namespace[:], s.journal.namespace) || lb.Epoch != l.epoch || lb.Owner != l.token || lb.Generation != l.generation || !lb.ExpiresAt.Equal(l.expires) {
		return risk.VelocityEligibility{}, identity.InvalidInputError{Field: "velocity_eligibility"}
	}
	b, err := s.nativeVerifier.NativeConfirmation(owned, exported, publication, confirmation, native)
	if err != nil || b != s.closureBinding(l, h.cut) {
		return risk.VelocityEligibility{}, identity.InvalidInputError{Field: "velocity_eligibility"}
	}
	result, err := s.journalIssuer.AcknowledgeEligibility(bounded, owned, exported, publication, confirmation, native, func(checkCtx context.Context) error {
		return r.CheckHealthy(checkCtx, healthy)
	})
	if err != nil {
		return risk.VelocityEligibility{}, velocityPublicationError(bounded, err)
	}
	return result, nil
}
