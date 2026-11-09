package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

var _ kernel.FeatureTerminalCleanupContributor = (*rpDenialPhase)(nil)

// CleanupFeatureTerminal disposes only the exact original RP custody after a
// failed denial transaction. It is not committed cancellation: the coordinator
// records a failed NotCommitted receipt and releases, rather than consumes,
// state. Historical cleanup uses authenticated metadata, never a live proof.
func (p *rpDenialPhase) CleanupFeatureTerminal(ctx context.Context, w kernel.Work) error {
	b, feature, transition, err := w.FeatureScope(p)
	if err != nil || p == nil || p.service == nil || feature != p.registration() || transition != rpDenialLifecycle() || b != p.historicalBinding() {
		return identity.ForbiddenError{}
	}
	state, err := w.OAuthCallbackDenialState(p)
	if err != nil {
		return identity.ForbiddenError{}
	}
	return p.eraseDenialExchangeSecrets(ctx, b, state, w)
}

func (p *rpDenialPhase) eraseDenialExchangeSecrets(ctx context.Context, b identity.CommandBinding, state kernel.CapabilityPlan, w interface {
	Exec(context.Context, string, ...any) (int64, error)
}) error {
	if p == nil || p.service == nil || b != p.historicalBinding() || state != p.flow.statePlan {
		return identity.ForbiddenError{}
	}
	return (&rpLinkPhase{service: p.service, flow: p.flow}).eraseExchangeSecrets(ctx, w)
}

func (p *rpDenialPhase) historicalBinding() identity.CommandBinding {
	b := p.flow.binding.Input.binding()
	op := rpDenialOperation()
	b.CommandID, b.CorrelationID = p.flow.binding.CallbackCommandID, string(p.flow.binding.CallbackCommandID)
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	return b
}
