package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// OAuthSigninContributor owns existing-account provider callback admission.
// Validation is pure and bounded: match original browser/state custody to the
// exact command and declared one-use input before preparation. Restored final
// commands additionally bind the authenticated provider result, selected account
// and prospective session. Metadata is not authentication.
// Apply and CheckFeatureCommit must enforce current account/factor/policy/risk
// authority and original deadlines; session, browser, state, audit and lifecycle
// effects share the existing coordinator's transaction. No external exchange or
// callback may run while Work holds primary locks.
type OAuthSigninContributor interface {
	FeatureCommitContributor
	ValidateOAuthSigninConsumption(identity.Command, CapabilityPlan) error
}

type oauthSigninConsumptionStage uint8

const (
	oauthSigninStateAbsent oauthSigninConsumptionStage = iota
	oauthSigninStateConsumed
	oauthSigninStateFinalized
)

func validateOAuthSigninConsumption(owner FeatureExecutionContributor, command identity.Command, plan CommandPlan) error {
	native, ok := owner.(OAuthSigninContributor)
	feature, present := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, bearer := command.SessionToken()
	if !ok || !present || !cookie || code || recovery || bearer || plan.Feature == nil || feature.Operation != oauthSigninAccountOperation() || plan.Feature.Operation != feature.Operation || plan.Capability == nil || plan.Capability.Purpose != "identity.oauth.callback" {
		return invalidPlan()
	}
	return native.ValidateOAuthSigninConsumption(command, *plan.Capability)
}

// OAuthSigninConsumption exposes original callback-state consumption only to
// the exact registered owner's synchronous Apply invocation, after the actual
// capability participant provisionally consumed it in this same transaction.
// Admission, final checks, recovery, foreign and returned Work deny. The owned
// scalar copy contains no bearer, grants no delivery permission and renews no
// validity. Session/browser effects and capability finalization may still fail.
func (w Work) OAuthSigninConsumption(owner FeatureExecutionContributor) (CapabilityReservationBinding, error) {
	binding, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || w.state.oauthSigninStage != oauthSigninStateConsumed {
		return CapabilityReservationBinding{}, invalidWork()
	}
	plan := w.state.execution.reservation.plan
	if plan.feature == nil || plan.feature.Operation != oauthSigninAccountOperation() || plan.capability == nil || plan.capability.Purpose != "identity.oauth.callback" || plan.capability.MaxUses != 1 {
		return CapabilityReservationBinding{}, invalidWork()
	}
	return CapabilityReservationBinding{Command: binding, Plan: *plan.capability, Fingerprint: fingerprint, Generation: generation}, nil
}

func prepareOAuthSigninConsumption(ctx context.Context, w Work) error {
	plan := w.state.execution.reservation.plan
	if plan.feature == nil || plan.feature.Operation != oauthSigninAccountOperation() || w.state.oauthSigninStage != oauthSigninStateAbsent {
		return w.fail(ctx, invalidPlan())
	}
	if err := w.state.execution.coordinator.runCapabilityExecution(ctx, w, false); err != nil {
		return err
	}
	w.state.oauthSigninStage = oauthSigninStateConsumed
	return nil
}

func (c *Coordinator) finalizeOAuthSigninConsumption(w Work) error {
	plan := w.state.execution.reservation.plan
	if plan.feature == nil || plan.feature.Operation != oauthSigninAccountOperation() || plan.capability == nil {
		return nil
	}
	if w.state.oauthSigninStage != oauthSigninStateConsumed || w.state.featureReceipt == nil || w.state.featureReceipt.Operation != oauthSigninAccountOperation() {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	w.state.oauthSigninStage = oauthSigninStateFinalized
	return nil
}
