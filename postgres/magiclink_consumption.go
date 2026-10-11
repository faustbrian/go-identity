package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// MagicLinkConsumptionContributor is the closed native passwordless login
// owner. Validation must exhaustively match original verified grant/issuance,
// pre-auth, callback, recipient and prospective-session custody to the command
// and declared one-use input; it is pure, bounded and must not perform IO.
// Apply and CheckFeatureCommit enforce current recipient/factor/risk authority,
// original exclusive expiry and complete session effects in the sole Work.
// Signature/origin validation belongs to the real capability owner, not these
// scalar declarations. No projection or method implementation grants authority.
type MagicLinkConsumptionContributor interface {
	FeatureCommitContributor
	ValidateMagicLinkConsumption(identity.Command, CapabilityPlan) error
}

func validateMagicLinkConsumption(owner FeatureExecutionContributor, command identity.Command, p CommandPlan) error {
	native, ok := owner.(MagicLinkConsumptionContributor)
	s, feature := command.Feature()
	if !ok || !feature || p.Feature == nil || p.Feature.Operation != magicLinkConsumeOperation() || s.Operation != p.Feature.Operation || p.Capability == nil || p.Capability.Purpose != "identity.magic-link.consume" {
		return invalidPlan()
	}
	return native.ValidateMagicLinkConsumption(command, *p.Capability)
}

// MagicLinkConsumption exposes frozen original one-use input only during the
// exact registered owner's protected Apply invocation, after the capability
// participant has provisionally consumed it in this same transaction. Zero,
// metadata-only, admission/commit/recovery, returned and foreign handles deny.
// Returned scalars are owned copies, contain no bearer and cannot authorize
// delivery: session/pre-auth, audit and capability finalization may still fail.
// Calls are serial within the invocation and perform no IO or renewal.
func (w Work) MagicLinkConsumption(owner FeatureExecutionContributor) (CapabilityReservationBinding, error) {
	b, fp, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || !w.state.magicLinkConsumed || w.state.magicLinkFinalized {
		return CapabilityReservationBinding{}, invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Operation != magicLinkConsumeOperation() || p.capability == nil || p.capability.Purpose != "identity.magic-link.consume" || p.capability.MaxUses != 1 {
		return CapabilityReservationBinding{}, invalidWork()
	}
	return CapabilityReservationBinding{Command: b, Plan: *p.capability, Fingerprint: fp, Generation: generation}, nil
}

func prepareMagicLinkConsumption(ctx context.Context, w Work) error {
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Operation != magicLinkConsumeOperation() || w.state.magicLinkConsumed || w.state.magicLinkFinalized {
		return w.fail(ctx, invalidPlan())
	}
	if err := w.state.execution.coordinator.runCapabilityExecution(ctx, w, false); err != nil {
		return err
	}
	w.state.magicLinkConsumed = true
	return nil
}

func (c *Coordinator) finalizeMagicLinkConsumption(w Work) error {
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Operation != magicLinkConsumeOperation() {
		return nil
	}
	if !w.state.magicLinkConsumed || w.state.magicLinkFinalized || w.state.featureReceipt == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	w.state.magicLinkFinalized = true
	return nil
}
