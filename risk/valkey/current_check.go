package valkey

import (
	"context"
	_ "embed"
	"encoding/hex"

	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/internal/velocity"
)

//go:embed current_check.lua
var currentCheckScriptBody string

var currentCheckScript = publicationProfileScript + currentCheckScriptBody

// checkCurrent is the read-only native half of current admission, including
// primary terminal replay which must never redispatch a pending/unknown attempt.
// It authenticates configured custody, brackets exact-marker/server-time IO with
// current primary eligibility and uses the existing transport's continuity owner.
// No counter, replay entry, marker, TTL, acknowledgement or authority is created
// or renewed. Success is momentary; mutateCurrent independently repeats current
// authority and atomically verifies its exact marker at the effect boundary.
func (r ownedRecovery) checkCurrent(ctx context.Context, command risk.CounterCommand, lease risk.VelocityLease, closure risk.VelocityClosure, publication risk.VelocityPublication, confirmation risk.VelocityConfirmation, native risk.VelocityNativeConfirmation, healthy risk.VelocityEligibility) error {
	if ctx == nil || r.transport == nil {
		return risk.ErrInvalidVelocityRecovery
	}
	bounded, cancel := context.WithTimeout(ctx, r.transport.config.timeout)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return err
	}
	verifier, err := r.issuer.Verifier()
	if err != nil {
		return err
	}
	lb, err := r.reader.Lease(lease)
	if err != nil || lb.Namespace != r.layout.replay.Namespace() || lb.Tenant != command.Bindings().Tenant {
		return risk.ErrInvalidVelocityRecovery
	}
	if _, err := r.layout.prepare(command, lb.Epoch); err != nil {
		return err
	}
	return r.checkCurrentMarker(bounded, verifier, lb, velocity.CurrentChain{Lease: lease, Closure: closure, Publication: publication, Confirmation: confirmation, Native: native, Eligibility: healthy})
}

// Callers authenticate original journal/command custody and bound context
// before entering this shared, strictly read-only marker crossing.
func (r ownedRecovery) checkCurrentMarker(ctx context.Context, verifier risk.VelocityNativeVerifier, lb risk.VelocityLeaseBinding, chain velocity.CurrentChain) error {
	b, err := verifier.Eligibility(ctx, chain.Lease, chain.Closure, chain.Publication, chain.Confirmation, chain.Native, chain.Eligibility)
	if err != nil {
		return err
	}
	original, err := ownedRecoveryMarker(lb)
	if err != nil {
		return err
	}
	expected := coveredPublicationMarker(original, b, "confirmed")
	key := "irv2:{" + r.layout.digest("identity-risk-valkey-slot-v1", lb.Tenant) + "}:health"
	reply, err := r.transport.executeScript(ctx, currentCheckScript, []string{key}, []string{expected})
	if err := recoveryAcknowledgement(reply, err, "current", hex.EncodeToString(b.ID[:])); err != nil {
		return err
	}
	_, err = verifier.Eligibility(ctx, chain.Lease, chain.Closure, chain.Publication, chain.Confirmation, chain.Native, chain.Eligibility)
	return err
}
