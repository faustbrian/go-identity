package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

// FeatureTerminalCleanupContributor supplies terminal erasure for the exact
// registered OAuth RP denial profile. It runs only after proven rollback or
// unanimous negative recovery, before canonical proof release. Cleanup, failure
// audit and the NotCommitted receipt share the coordinator transaction. The
// trusted owner may use FeatureScope during this invocation, not Apply-only
// command authority. It must not exchange, issue access, renew authority, close
// or retain Work. Missing cleanup, errors and panics keep custody recoverable.
// Other feature profiles do not acquire a cleanup phase through this interface.
type FeatureTerminalCleanupContributor interface {
	FeatureExecutionContributor
	CleanupFeatureTerminal(context.Context, Work) error
}

// OAuthCallbackDenialState returns frozen original-state metadata only during
// this exact denial owner's terminal cleanup invocation. It grants no proof,
// execution or consumption authority; foreign and returned handles fail.
func (w Work) OAuthCallbackDenialState(owner FeatureTerminalCleanupContributor) (CapabilityPlan, error) {
	_, feature, _, err := w.FeatureScope(owner)
	if err != nil || !oauthCallbackDenialSelected(feature.Operation) || feature.Contributor != oauthCallbackDenialDescriptor() || w.state.featureApplying || w.state.featureAttempted || w.state.execution == nil || w.state.execution.reservation == nil || w.state.execution.reservation.plan == nil || w.state.execution.reservation.plan.capability == nil {
		return CapabilityPlan{}, invalidWork()
	}
	return *w.state.execution.reservation.plan.capability, nil
}

// OAuthCallbackDenialState returns the same immutable state metadata to the
// exact registered native denial owner during historical negative-evidence
// collection. There is no restoration or renewal of a usable proof.
func (w RecoveryWork) OAuthCallbackDenialState(owner FeatureTerminalCleanupContributor) (CapabilityPlan, error) {
	_, feature, _, err := w.FeatureScope(owner)
	if err != nil || !oauthCallbackDenialSelected(feature.Operation) || feature.Contributor != oauthCallbackDenialDescriptor() || w.state.plan.capability == nil {
		return CapabilityPlan{}, invalidWork()
	}
	return *w.state.plan.capability, nil
}

// RecoverOAuthCallbackDenial is the exact registered native owner's historical
// seam, not an application query-policy caller. It returns only the retained
// failure/denial receipt or bounded pending observation. It neither authenticates
// a user nor grants execution authority. The owner must first authenticate the
// retained RP metadata. Scope mismatch, missing/foreign registrations and
// unsupported profiles fail before recovery; the existing coordinator owns
// fencing, unanimous negative evidence, cleanup, proof release and receipt.
func (c *Coordinator) RecoverOAuthCallbackDenial(ctx context.Context, q identity.RecoveryQuery, owner FeatureTerminalCleanupContributor) (identity.CommandResult, error) {
	if c == nil || ctx == nil || c.registry == nil || q.OperationID != oauthCallbackDenialOperation().OperationID || q.RecordID == "" || q.UserID == "" || string(q.ActorID) != string(q.UserID) {
		return identity.CommandResult{}, invalidPlan()
	}
	entry, err := c.registry.selectFeatureOperation(FeatureRegistration{Contributor: oauthCallbackDenialDescriptor(), Operation: oauthCallbackDenialOperation()})
	if err != nil || !sameParticipant(entry.contributor, owner) {
		return identity.CommandResult{}, invalidPlan()
	}
	result, err := c.recoverCommandReceipt(ctx, q)
	return coreCreationReceipt(result, err)
}

func (c *Coordinator) cleanupFeatureTerminal(ctx context.Context, w Work) (err error) {
	if !c.owns(w) || w.usable() != nil {
		return invalidWork()
	}
	p := w.state.execution.reservation.plan
	if p.feature == nil || !oauthCallbackDenialSelected(p.feature.Operation) {
		return nil
	}
	if p.feature.Contributor != oauthCallbackDenialDescriptor() || p.capability == nil || p.accountLink != nil {
		return w.fail(ctx, invalidPlan())
	}
	entry, err := c.registry.selectFeatureOperation(*p.feature)
	if err != nil {
		return w.fail(ctx, invalidPlan())
	}
	owner, ok := entry.contributor.(FeatureTerminalCleanupContributor)
	if !ok {
		return w.fail(ctx, identity.UnavailableError{})
	}
	w.state.featureInvocation = owner
	defer func() {
		w.state.featureInvocation = nil
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if err = owner.CleanupFeatureTerminal(ctx, w); err != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	if w.state.rows != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.usable()
}
