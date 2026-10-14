package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// MFACompletionContributor is the native owner of the session-producing
// alternative of a named factor operation. Validation is pure and bounded and
// must match the real verified continuation, original primary/browser/remember
// scope and immutable factor submission to this command and declaration. Apply
// must fence current authority and shared attempts, verify/consume the selected
// factor, advance the continuation and persist the original-primary session
// effects in this same Work. CheckFeatureCommit rechecks current validity and
// absolute expiry. No method or scalar declaration itself authenticates a factor.
type MFACompletionContributor interface {
	FeatureCommitContributor
	ValidateMFACompletion(identity.Command, CapabilityPlan, MFACompletionPlan) error
}

func validateMFACompletion(owner FeatureExecutionContributor, command identity.Command, p CommandPlan) error {
	native, ok := owner.(MFACompletionContributor)
	s, feature := command.Feature()
	if !ok || !feature || p.Feature == nil || s.Operation != p.Feature.Operation || s.Binding.OperationID != p.Feature.Operation.OperationID || !validMFACompletionPlan(s.Binding, p) {
		return invalidPlan()
	}
	return native.ValidateMFACompletion(command, *p.Capability, *p.MFACompletion)
}

// MFACompletionConsumption exposes the original child consumption and frozen
// continuation only during the exact registered owner's protected Apply, after
// provisional one-use consumption in this transaction. Zero, foreign, returned,
// preparation, final-check, recovery and finalized handles deny. Owned scalar
// copies contain no factor or bearer and cannot authorize a session alone.
// This guard performs no IO, factor verification, expiry renewal or commit.
func (w Work) MFACompletionConsumption(owner MFACompletionContributor) (CapabilityReservationBinding, MFACompletionPlan, error) {
	b, fp, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || !w.state.mfaConsumed || w.state.mfaFinalized {
		return CapabilityReservationBinding{}, MFACompletionPlan{}, invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.feature == nil || !mfaCompletionOperation(p.feature.Operation) || p.mfaCompletion == nil || p.capability == nil || p.capability.Purpose != "identity.mfa.complete" || p.capability.MaxUses != 1 || p.capability.CapabilityID != string(p.mfaCompletion.ID) || p.lifecycle == nil || p.lifecycle.EventType != "session.created.v1" {
		return CapabilityReservationBinding{}, MFACompletionPlan{}, invalidWork()
	}
	return CapabilityReservationBinding{Command: b, Plan: *p.capability, Fingerprint: fp, Generation: generation}, *p.mfaCompletion, nil
}

func prepareMFACompletionConsumption(ctx context.Context, w Work) error {
	p := w.state.execution.reservation.plan
	if p.mfaCompletion == nil || p.feature == nil || !mfaCompletionOperation(p.feature.Operation) || w.state.mfaConsumed || w.state.mfaFinalized {
		return w.fail(ctx, invalidPlan())
	}
	if err := w.state.execution.coordinator.runCapabilityExecution(ctx, w, false); err != nil {
		return err
	}
	w.state.mfaConsumed = true
	return nil
}

func (c *Coordinator) finalizeMFACompletionConsumption(w Work) error {
	p := w.state.execution.reservation.plan
	if p.mfaCompletion == nil {
		return nil
	}
	if !w.state.mfaConsumed || w.state.mfaFinalized || w.state.featureReceipt == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	w.state.mfaFinalized = true
	return nil
}
