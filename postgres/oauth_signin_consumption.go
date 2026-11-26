package postgres

import (
	"context"

	"github.com/faustbrian/go-capability/v2"
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

// OneTapCallbackContributor owns native Google One Tap completion. It binds the
// exact original one-use browser grant to the selected anonymous flow before
// preparation. The native owner performs credential verification outside Work
// and fences its verified account, original browser, risk and session effects
// in the single admitted transaction. It does not own capability replay.
type OneTapCallbackContributor interface {
	FeatureAdmissionPreparationContributor
	FeatureCommitContributor
	ValidateOneTapCallbackConsumption(identity.Command, CapabilityPlan) error
}

// SSOOIDCSigninContributor owns enterprise callback consumption and its
// final native effects. Its validation binds the original browser and one-use
// enterprise grant to the exact start transaction, independently of social
// OAuth. Generation may exchange only after the coordinator acknowledges the
// original reservation. Apply and CheckFeatureCommit must enforce current
// provider, member, account and session policy using that same transaction.
type SSOOIDCSigninContributor interface {
	FeatureCommitContributor
	ValidateSSOOIDCSigninConsumption(identity.Command, CapabilityPlan) error
}

// SSOOAuth2SigninContributor is the separate native enterprise OAuth callback
// owner. It validates the original browser and one-use proof declaration before
// preparation and fences the verified provider subject and current membership in
// Work. The provider exchange runs only after acknowledged reservation, never
// while the coordinator holds primary locks.
type SSOOAuth2SigninContributor interface {
	FeatureCommitContributor
	ValidateSSOOAuth2SigninConsumption(identity.Command, CapabilityPlan) error
}

// SSOSAMLSigninContributor owns the exact SAML frontchannel callback. Its
// admission binds the original browser and capability to the registered ACS.
// Apply and final checks must keep current provider/member authority and the
// response/assertion replay set in the same Work as the session. The original
// capability may remain internal when RelayState is absent.
type SSOSAMLSigninContributor interface {
	FeatureAdmissionPreparationContributor
	FeatureCommitContributor
	ValidateSSOSAMLSigninConsumption(identity.Command, CapabilityPlan) error
}

// SSOSAMLIDPConfirmationContributor owns a pending, unsolicited SAML
// confirmation. Validate the exact paired browser/form custody and original
// one-use declaration during admission. Apply and the final check must fence
// that pending record and current provider, account and member authority. The
// confirmation, both replay IDs and session effects must share the actual Work.
type SSOSAMLIDPConfirmationContributor interface {
	FeatureAdmissionPreparationContributor
	FeatureCommitContributor
	ValidateSSOSAMLIDPConfirmationConsumption(identity.Command, CapabilityPlan) error
}

// SSOOIDCExplicitLinkContributor owns only the authenticated enterprise link
// variant. Validation must bind the original session and one-use browser
// transaction to the same user, provider and proof. Its final Work check owns
// current session/consent, organization and provider authority. It must not
// create a session or select a local identity from provider claims.
type SSOOIDCExplicitLinkContributor interface {
	FeatureCommitContributor
	ValidateSSOOIDCExplicitLinkConsumption(identity.Command, CapabilityPlan) error
}

type oauthSigninConsumptionStage uint8

const (
	oauthSigninStateAbsent oauthSigninConsumptionStage = iota
	oauthSigninStateConsumed
	oauthSigninStateFinalized
)

func validateProviderSigninConsumption(owner FeatureExecutionContributor, command identity.Command, plan CommandPlan) error {
	if plan.Feature != nil && plan.Feature.Operation == SSOSAMLIDPConfirmationOperation() {
		feature, present := command.SAMLIDPConfirmationFeature()
		native, selected := owner.(SSOSAMLIDPConfirmationContributor)
		if !present || !selected || feature.Operation != plan.Feature.Operation || !providerSigninPreparation(plan) || !validSSOSAMLIDPConfirmationBinding(feature.Binding) {
			return invalidPlan()
		}
		return native.ValidateSSOSAMLIDPConfirmationConsumption(command, *plan.Capability)
	}
	feature, present := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, bearer := command.SessionToken()
	if !present || code || recovery || !providerSigninPreparation(plan) || plan.Feature.Operation != feature.Operation {
		return invalidPlan()
	}
	if feature.Operation == SSOOIDCExplicitLinkCallbackOperation() {
		if native, ok := owner.(SSOOIDCExplicitLinkContributor); ok && bearer && !cookie && validSSOOIDCExplicitLinkBinding(feature.Binding) {
			return native.ValidateSSOOIDCExplicitLinkConsumption(command, *plan.Capability)
		}
		return invalidPlan()
	}
	if !cookie || bearer {
		return invalidPlan()
	}
	switch feature.Operation {
	case oauthSigninAccountOperation():
		if native, ok := owner.(OAuthSigninContributor); ok {
			return native.ValidateOAuthSigninConsumption(command, *plan.Capability)
		}
	case OneTapCallbackOperation():
		if native, ok := owner.(OneTapCallbackContributor); ok && validOneTapCallbackBinding(feature.Binding) {
			return native.ValidateOneTapCallbackConsumption(command, *plan.Capability)
		}
	case ssoOIDCSigninOperation():
		if native, ok := owner.(SSOOIDCSigninContributor); ok && validSSOOIDCSigninBinding(feature.Binding) {
			return native.ValidateSSOOIDCSigninConsumption(command, *plan.Capability)
		}
	case SSOOAuth2SigninOperation():
		if native, ok := owner.(SSOOAuth2SigninContributor); ok && validSSOOAuth2SigninBinding(feature.Binding) {
			return native.ValidateSSOOAuth2SigninConsumption(command, *plan.Capability)
		}
	case SSOSAMLSigninOperation():
		if native, ok := owner.(SSOSAMLSigninContributor); ok && validEnterpriseSigninBinding(feature.Binding, feature.Operation) {
			return native.ValidateSSOSAMLSigninConsumption(command, *plan.Capability)
		}
	}
	return invalidPlan()
}

// OAuthSigninConsumption exposes original callback-state consumption only to
// the exact registered owner's synchronous Apply invocation, after the actual
// capability participant provisionally consumed it in this same transaction.
// Admission, final checks, recovery, foreign and returned Work deny. The owned
// scalar copy contains no bearer, grants no delivery permission and renews no
// validity. Session/browser effects and capability finalization may still fail.
func (w Work) OAuthSigninConsumption(owner FeatureExecutionContributor) (CapabilityReservationBinding, error) {
	return w.providerSigninConsumption(owner, oauthSigninAccountOperation())
}

// OneTapCallbackConsumption exposes only the exact provisionally consumed
// browser grant during the registered native callback's synchronous Apply.
// It cannot be used from a generic callback, final check or recovery, and
// grants no browser, current account or session authority.
func (w Work) OneTapCallbackConsumption(owner FeatureExecutionContributor) (CapabilityReservationBinding, error) {
	return w.providerSigninConsumption(owner, OneTapCallbackOperation())
}

// SSOOIDCSigninConsumption exposes the exact enterprise state already consumed
// provisionally by the capability owner during this native Apply invocation.
// It does not expose verifier or bearer bytes, allow social substitution, or
// establish provider, linked-account, membership or final session authority.
func (w Work) SSOOIDCSigninConsumption(owner FeatureExecutionContributor) (CapabilityReservationBinding, error) {
	return w.providerSigninConsumption(owner, ssoOIDCSigninOperation())
}

// SSOOAuth2SigninConsumption exposes the exact enterprise OAuth state consumed
// provisionally in synchronous Apply. OIDC and social proofs, foreign Work and
// non-Apply invocations deny; the returned copy grants no session authority.
func (w Work) SSOOAuth2SigninConsumption(owner FeatureExecutionContributor) (CapabilityReservationBinding, error) {
	return w.providerSigninConsumption(owner, SSOOAuth2SigninOperation())
}

// SSOSAMLSigninConsumption exposes the original capability provisionally
// consumed inside the exact native ACS Apply. It grants no replay, browser,
// provider or session authority and never renews the capability's lifetime.
func (w Work) SSOSAMLSigninConsumption(owner FeatureExecutionContributor) (CapabilityReservationBinding, error) {
	return w.providerSigninConsumption(owner, SSOSAMLSigninOperation())
}

// SSOSAMLIDPConfirmationConsumption exposes the specific confirmation
// capability already consumed provisionally inside its selected native Apply.
// It confers no browser, replay or session authority. Its lifetime is the
// original capability cutoff and no other feature's consumption can alias it.
func (w Work) SSOSAMLIDPConfirmationConsumption(owner FeatureExecutionContributor) (CapabilityReservationBinding, error) {
	return w.providerSigninConsumption(owner, SSOSAMLIDPConfirmationOperation())
}

func (w Work) providerSigninConsumption(owner FeatureExecutionContributor, operation identity.FeatureOperation) (CapabilityReservationBinding, error) {
	binding, fingerprint, generation, err := w.FeatureCommandIdentity(owner)
	if err != nil || w.state.oauthSigninStage != oauthSigninStateConsumed {
		return CapabilityReservationBinding{}, invalidWork()
	}
	plan := w.state.execution.reservation.plan
	if plan.feature == nil || plan.feature.Operation != operation || plan.capability == nil || plan.capability.Purpose != capability.Purpose(operation.OperationID) || plan.capability.MaxUses != 1 {
		return CapabilityReservationBinding{}, invalidWork()
	}
	return CapabilityReservationBinding{Command: binding, Plan: *plan.capability, Fingerprint: fingerprint, Generation: generation}, nil
}

func prepareProviderSigninConsumption(ctx context.Context, w Work) error {
	plan := w.state.execution.reservation.plan
	if plan.feature == nil || !providerSigninConsumptionOperation(plan.feature.Operation) || w.state.oauthSigninStage != oauthSigninStateAbsent {
		return w.fail(ctx, invalidPlan())
	}
	if err := w.state.execution.coordinator.runCapabilityExecution(ctx, w, false); err != nil {
		return err
	}
	w.state.oauthSigninStage = oauthSigninStateConsumed
	return nil
}

func (c *Coordinator) finalizeProviderSigninConsumption(w Work) error {
	plan := w.state.execution.reservation.plan
	if plan.feature == nil || !providerSigninConsumptionOperation(plan.feature.Operation) || plan.capability == nil {
		return nil
	}
	if w.state.oauthSigninStage != oauthSigninStateConsumed || w.state.featureReceipt == nil || w.state.featureReceipt.Operation != plan.feature.Operation {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := c.runCapabilityExecution(w.state.ctx, w, true); err != nil {
		return err
	}
	w.state.oauthSigninStage = oauthSigninStateFinalized
	return nil
}
