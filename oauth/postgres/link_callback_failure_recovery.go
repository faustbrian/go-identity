package postgres

import (
	"context"
	"encoding/base64"
	"errors"

	auditpg "github.com/faustbrian/go-audit/postgres"
	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	lifecyclepg "github.com/faustbrian/go-transactional-outbox/postgres/identity"
	"github.com/jackc/pgx/v5"
)

// recoverExpiredProviderFailure is the maintenance integration seam after
// expiredRecoveryFlow authenticates the candidate's retained metadata. It uses
// the existing exact registered native owners, never a fabricated public query
// caller or restored proof. Known denial/refusal and attached-output failures
// settle through the canonical coordinator; unattached uncertainty stays pending.
// Missing/foreign claim purposes are left for the caller's ordinary handling.
func (s *LinkService) recoverExpiredProviderFailure(ctx context.Context, flow rpCallbackFlow) (identity.CommandResult, bool, error) {
	spec, err := callbackSpecification(flow)
	if err != nil || s == nil || s.pool == nil || ctx == nil {
		return identity.CommandResult{}, false, identity.ForbiddenError{}
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(flow.binding.CallbackCommandID))
	if err != nil {
		return identity.CommandResult{}, false, identity.ForbiddenError{}
	}
	var purpose string
	err = s.pool.Raw().QueryRow(ctx, `SELECT purpose FROM identity.identity_command_id_claims WHERE command_id=$1 AND tenant_id=$2`, id, string(spec.Binding.TenantID)).Scan(&purpose)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.CommandResult{}, false, nil
	}
	if err != nil {
		return identity.CommandResult{}, false, identity.UnavailableError{}
	}
	if purpose == "identity.account.link-token" {
		owner, _, err := s.callbackCoordinator(&rpLinkPhase{service: s, flow: flow})
		if err != nil {
			return identity.CommandResult{}, true, err
		}
		result, err := owner.Recover(ctx, rpFailureRecoveryQuery(spec.Binding))
		return result, true, err
	}
	if purpose != rpDenialOperation().OperationID {
		return identity.CommandResult{}, false, nil
	}
	phase := &rpDenialPhase{service: s, flow: flow}
	auditing, err := auditpg.NewIdentityContributor(auditpg.Config{})
	if err != nil {
		return identity.CommandResult{}, true, err
	}
	lifecycle, err := lifecyclepg.NewContributor()
	if err != nil {
		return identity.CommandResult{}, true, err
	}
	registry, err := kernel.NewContributorRegistry([]kernel.Contributor{s.directory, auditing, lifecycle, phase, capabilitypg.NewParticipant()})
	if err != nil {
		return identity.CommandResult{}, true, err
	}
	coordinator, err := kernel.NewCoordinator(s.pool, registry, s.config().Coordinator)
	if err != nil {
		return identity.CommandResult{}, true, err
	}
	result, err := coordinator.RecoverOAuthCallbackDenial(ctx, rpFailureRecoveryQuery(phase.historicalBinding()), phase)
	return result, true, err
}

func rpFailureRecoveryQuery(b identity.CommandBinding) identity.RecoveryQuery {
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
}
