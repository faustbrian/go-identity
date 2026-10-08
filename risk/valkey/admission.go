package valkey

import (
	"context"

	"github.com/faustbrian/go-identity/risk"
)

// mutateCurrent is the owned native crossing, not a public CounterStore. The
// composition owner must journal intent before invoking it and conserve the
// returned effect afterward, including effects accompanied by an error.
// Current primary checks end before native IO; exact-marker and continuity
// checks remain owned by the existing atomic script/transport. No replay-only
// callback, caller epoch, marker or health assertion grants traffic authority.
func (r ownedRecovery) mutateCurrent(ctx context.Context, command risk.CounterCommand, lease risk.VelocityLease, closure risk.VelocityClosure, publication risk.VelocityPublication, confirmation risk.VelocityConfirmation, native risk.VelocityNativeConfirmation, healthy risk.VelocityEligibility) (risk.CounterResult, error) {
	if ctx == nil || r.transport == nil {
		return risk.CounterResult{}, risk.ErrInvalidVelocityRecovery
	}
	bounded, cancel := context.WithTimeout(ctx, r.transport.config.timeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return risk.CounterResult{}, err
	}
	verifier, err := r.issuer.Verifier()
	if err != nil {
		return risk.CounterResult{}, err
	}
	lb, err := r.reader.Lease(lease)
	if err != nil || lb.Namespace != r.layout.replay.Namespace() || lb.Tenant != command.Bindings().Tenant {
		return risk.CounterResult{}, risk.ErrInvalidVelocityRecovery
	}
	// Authenticate the command before the primary checker performs any IO.
	if _, err := r.layout.prepare(command, lb.Epoch); err != nil {
		return risk.CounterResult{}, err
	}
	b, err := verifier.Eligibility(bounded, lease, closure, publication, confirmation, native, healthy)
	if err != nil {
		return risk.CounterResult{}, err
	}
	original, err := ownedRecoveryMarker(lb)
	if err != nil {
		return risk.CounterResult{}, err
	}
	expected := coveredPublicationMarker(original, b, "confirmed")
	dispatch := mutationDispatcher{layout: r.layout, timeout: r.transport.config.timeout, execute: r.transport.execute}
	result, err := dispatch.mutate(bounded, command, lb.Epoch, expected)
	if err != nil {
		return result, err
	}
	// A later primary failure denies admission, never erases acknowledged commit
	// truth or grants permission to resend. The journal must retain that result.
	_, err = verifier.Eligibility(bounded, lease, closure, publication, confirmation, native, healthy)
	return result, err
}
