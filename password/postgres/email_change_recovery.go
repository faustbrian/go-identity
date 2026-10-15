package passwordpostgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
)

// ChangeRecover observes exact original change history under current query
// policy. It needs no expired proof/live old session and cannot re-execute,
// notify, reveal an address or renew authority. Unknown reconciliation stays
// unknown; ownership, bounded cancellation and errors match VerificationRecover.
func (s *EmailManagementService) ChangeRecover(ctx context.Context, r email.ChangeRecoveryRequest) (out email.ChangeRecoveryResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.primary == nil || s.primary.config.Action != "identity.email.change-request" || r.Validate() != nil {
		return out, email.ErrInvalidVerification
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	q, _ := r.Recovery.Bindings()
	caller := r.Caller.Clone()
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(q.UserID)
	}
	coordinator, _, err := s.managedConfirmationCoordinator(&managedEmailConfirmationPhase{service: s})
	if err != nil {
		return out, identity.UnavailableError{}
	}
	result, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	if result.Outcome == identity.CommitOutcomeInvalid {
		return out, err
	}
	out = email.ChangeRecoveryResult{Outcome: result.Outcome, RetryAfter: result.RetryAfter, Recovery: r.Recovery}
	if out.Validate() != nil {
		return out, identity.UnavailableError{}
	}
	return out, err
}
