package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// OrganizationInvitationConsumptionContributor is the closed native invitation
// owner. Pure validation matches the original verified grant, invitation,
// recipient, organization and command; scalar declarations are not proof.
// ApplyFeature must fence current recipient/session/organization/policy and
// persist invitation acceptance plus membership in the sole Work. Its commit
// check repeats current authority and original exclusive expiry. The capability
// participant alone verifies and atomically consumes the original proof.
type OrganizationInvitationConsumptionContributor interface {
	FeatureCommitContributor
	ValidateOrganizationInvitationConsumption(identity.Command, CapabilityPlan) error
}

func validateOrganizationInvitationConsumption(owner FeatureExecutionContributor, command identity.Command, plan CommandPlan) error {
	native, ok := owner.(OrganizationInvitationConsumptionContributor)
	s, feature := command.Feature()
	if !ok || !feature || plan.Feature == nil || plan.Feature.Contributor != organizationInvitationDescriptor() || plan.Feature.Operation != organizationInvitationAcceptOperation() || s.Operation != plan.Feature.Operation || plan.Capability == nil || string(plan.Capability.Purpose) != organizationInvitationAcceptOperation().OperationID {
		return invalidPlan()
	}
	return native.ValidateOrganizationInvitationConsumption(command, *plan.Capability)
}

// OrganizationInvitationConsumption returns owned original reservation custody
// only during the exact invitation owner's protected Apply, after provisional
// one-use consumption. Preparation, commit checks, recovery, returned/foreign
// handles and finalized work deny. It performs no IO or renewal, contains no
// bearer and is not a committed membership or authorization grant.
func (w Work) OrganizationInvitationConsumption(owner OrganizationInvitationConsumptionContributor) (CapabilityReservationBinding, error) {
	b, fp, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || !w.state.invitationConsumed || w.state.invitationFinalized {
		return CapabilityReservationBinding{}, invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Contributor != organizationInvitationDescriptor() || p.feature.Operation != organizationInvitationAcceptOperation() || p.capability == nil || string(p.capability.Purpose) != organizationInvitationAcceptOperation().OperationID || p.capability.MaxUses != 1 {
		return CapabilityReservationBinding{}, invalidWork()
	}
	return CapabilityReservationBinding{Command: b, Plan: *p.capability, Fingerprint: fp, Generation: generation}, nil
}

func prepareOrganizationInvitationConsumption(ctx context.Context, w Work) error {
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Operation != organizationInvitationAcceptOperation() || w.state.invitationConsumed || w.state.invitationFinalized {
		return w.fail(ctx, invalidPlan())
	}
	if err := w.state.execution.coordinator.runCapabilityExecution(ctx, w, false); err != nil {
		return err
	}
	w.state.invitationConsumed = true
	return nil
}

func (c *Coordinator) finalizeOrganizationInvitationConsumption(w Work) error {
	p := w.state.execution.reservation.plan
	if p.feature == nil || p.feature.Operation != organizationInvitationAcceptOperation() {
		return nil
	}
	if !w.state.invitationConsumed || w.state.invitationFinalized || w.state.featureReceipt == nil || w.state.invitationMembership == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	w.state.invitationFinalized = true
	return nil
}
