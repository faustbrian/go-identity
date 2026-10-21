package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// AnonymousUpgradeContributor is the closed native upgrade owner. Its pure
// bounded validation must bind the original permanent-target credential, guest
// possession, typed merge decisions and one-use declaration to the exact command.
// ApplyFeature must fence both identities and current policy, dispose only the
// guest through the kernel owner, persist the anonymous transition and replace
// its sessions through the session owner, all in the sole Work. Commit checks
// repeat current authority and earliest original expiry without renewal. The
// capability participant, not scalar metadata, verifies and consumes the proof.
type AnonymousUpgradeContributor interface {
	FeatureCommitContributor
	ValidateAnonymousUpgrade(identity.Command, CapabilityPlan) error
}

func validateAnonymousUpgrade(owner FeatureExecutionContributor, command identity.Command, p CommandPlan) error {
	native, ok := owner.(AnonymousUpgradeContributor)
	s, feature := command.Feature()
	if !ok || !feature || p.Feature == nil || p.Feature.Contributor != anonymousCreationDescriptor() || p.Feature.Operation != anonymousUpgradeOperation() || s.Operation != p.Feature.Operation || p.Capability == nil || p.Capability.Purpose != "identity.anonymous.upgrade" {
		return invalidPlan()
	}
	return native.ValidateAnonymousUpgrade(command, *p.Capability)
}

// AnonymousUpgradeConsumption returns owned original one-use custody only
// during the exact registered upgrade owner's Apply after provisional capability
// consumption. Preparation, final checks, recovery, foreign/returned handles and
// finalized Work deny. It performs no IO, carries no bearer, renews nothing and
// cannot prove commitment or authorize delivery of the permanent session.
func (w Work) AnonymousUpgradeConsumption(owner AnonymousUpgradeContributor) (CapabilityReservationBinding, error) {
	b, fp, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || !w.state.anonymousUpgradeConsumed || w.state.anonymousUpgradeFinalized {
		return CapabilityReservationBinding{}, invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Contributor != anonymousCreationDescriptor() || p.feature.Operation != anonymousUpgradeOperation() || p.capability == nil || p.capability.Purpose != "identity.anonymous.upgrade" || p.capability.MaxUses != 1 {
		return CapabilityReservationBinding{}, invalidWork()
	}
	return CapabilityReservationBinding{Command: b, Plan: *p.capability, Fingerprint: fp, Generation: generation}, nil
}

func prepareAnonymousUpgradeConsumption(ctx context.Context, w Work) error {
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Operation != anonymousUpgradeOperation() || w.state.anonymousUpgradeConsumed || w.state.anonymousUpgradeFinalized {
		return w.fail(ctx, invalidPlan())
	}
	if err := w.state.execution.coordinator.runCapabilityExecution(ctx, w, false); err != nil {
		return err
	}
	w.state.anonymousUpgradeConsumed = true
	return nil
}

func (c *Coordinator) finalizeAnonymousUpgradeConsumption(w Work) error {
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Operation != anonymousUpgradeOperation() {
		return nil
	}
	if !w.state.anonymousUpgradeConsumed || w.state.anonymousUpgradeFinalized || w.state.featureReceipt == nil || w.state.anonymousDisposal == nil || string(w.state.anonymousDisposal.after.ID) != w.state.binding.RecordID {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	w.state.anonymousUpgradeFinalized = true
	return nil
}
