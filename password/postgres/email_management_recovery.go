package passwordpostgres

import (
	"context"
	"slices"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
)

// VerificationSendRecover reads or reconciles the exact original add/resend
// command through the existing coordinator journal and current disclosure policy.
// The caller must name the original tenant, human actor, user and address; an old
// session or password proof is not recovery authority. Returned versions are
// acknowledged historical metadata, never current address ownership. Unknown
// outcomes disclose no address. This method cannot generate another link, renew
// proof freshness, issue a session or send mail. Calls borrow the pool, retain no
// handles and honor MaximumDuration and earlier cancellation.
func (s *EmailManagementService) VerificationSendRecover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out EmailManagementResult, err error) {
	return s.recoverManagedRequest(ctx, q, caller, "identity.email.verification-send")
}

// ChangeRequestRecover observes the exact committed pending-candidate request
// under current policy, without an old session/proof or new issuance. It cannot
// complete the primary change or send another message. Metadata, cancellation,
// unknown-outcome and ownership semantics match VerificationSendRecover.
func (s *EmailManagementService) ChangeRequestRecover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (EmailManagementResult, error) {
	return s.recoverManagedRequest(ctx, q, caller, "identity.email.change-request")
}

func (s *EmailManagementService) recoverManagedRequest(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, action string) (out EmailManagementResult, err error) {
	out.CommandID = q.CommandID
	if ctx == nil || s == nil || s.primary == nil || s.config == nil || s.primary.config.Action != action || q.OperationID != action || q.ActorKind != authorization.SubjectUser || string(q.ActorID) != string(q.UserID) || q.UserID == "" || q.RecordID == "" || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return out, password.ErrPasswordWork
	}
	ctx, stop := context.WithTimeout(ctx, min(s.config().MaximumDuration, time.Minute))
	defer stop()
	defer func() {
		if recover() != nil {
			out = EmailManagementResult{CommandID: q.CommandID}
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	p := &emailManagementPhase{service: s}
	coordinator, _, err := s.coordinator(p)
	if err != nil {
		return out, err
	}
	result, err := coordinator.RecoverFeatureCommand(ctx, q, caller)
	out.Outcome = result.Outcome
	out.RetryAfter = result.RetryAfter
	if err == nil && result.Outcome == identity.CommitOutcomeCommitted && result.Feature != nil {
		if !slices.Contains(p.FeatureOperations(), result.Feature.Operation) || result.Feature.AfterVersion == 0 {
			return EmailManagementResult{CommandID: q.CommandID}, identity.ForbiddenError{}
		}
		out.AddressID = identity.IdentifierID(q.RecordID)
		out.IdentifierVersion, out.VerificationVersion = result.Feature.AfterVersion, result.Feature.AfterVersion
	}
	return out, err
}
