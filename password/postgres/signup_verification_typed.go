package passwordpostgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
)

var _ email.RegistrationVerificationService = (*SignupService)(nil)

// VerificationConfirm binds the email-owned typed registration port to the
// existing native confirmation coordinator. It introduces no journal, proof
// consumption owner or session issuer. Request tenant/caller/network provenance
// must be trusted; the signed original grant selects any omitted user target.
//
// One deadline covers confirmation and subsequent disclosure. A fresh committed
// invocation rechecks current recovery policy and reads the primary identifier
// partition before returning the exact verified address/version. Replay returns
// metadata only. A later error, cancellation or panic clears confidential output
// but conserves any known durable outcome and original recovery correlation.
// The result is not current authentication or cached validity evidence. This
// require-before-signin profile issues no session and owns no goroutines.
func (s *SignupService) VerificationConfirm(ctx context.Context, request email.VerificationConfirmRequest) (out email.VerificationConfirmResult, err error) {
	if ctx == nil || s == nil || s.config == nil || s.pool == nil || s.directory == nil || request.Validate() != nil {
		return out, email.ErrInvalidVerification
	}
	ctx, cancel := context.WithTimeout(ctx, s.config().Repository.MaximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			out.Address = identity.IdentifierProjection{}
		}
	}()
	var replayed bool
	receipt, executionErr := s.confirmRegistrationVerification(ctx, request.Token, request.Callback.String(), request.CommandID, request.Network, request.Caller, &replayed)
	out.Outcome, out.RetryAfter, out.Replayed = receipt.Outcome, receipt.RetryAfter, replayed
	if receipt.Outcome == identity.CommitOutcomeInvalid {
		return out, executionErr
	}
	q := confirmationRecoveryQuery(receipt)
	out.Recovery, err = email.NewVerificationRecovery(q)
	if err != nil {
		return out, identity.UnavailableError{}
	}
	if q.CommandID != request.CommandID || q.TenantID != request.TenantID || q.ActorID != identity.ActorID(request.Caller.Request.Subject.ID) || q.ActorKind != request.Caller.Request.Subject.Kind {
		return out, identity.UnavailableError{}
	}
	// Constructing correlation must not erase the executor's classification,
	// including a known commit followed by cancellation or cleanup failure.
	if executionErr != nil {
		return out, executionErr
	}
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		return out, identity.UnavailableError{}
	}
	if replayed {
		return out, nil
	}
	caller := request.Caller
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(q.UserID)
	}
	history, err := s.RecoverRegistrationVerification(ctx, q, caller)
	if err != nil {
		return out, err
	}
	if history.Outcome != identity.CommitOutcomeCommitted || history.Binding != receipt.Binding || history.Feature == nil || receipt.Feature == nil || *history.Feature != *receipt.Feature {
		return out, identity.UnavailableError{}
	}
	state, err := s.directory.GetIdentifierState(ctx, identity.IdentifierQuery{TenantID: q.TenantID, UserID: q.UserID, MaximumIdentifiers: 128})
	if err != nil {
		return out, err
	}
	var at time.Time
	if err := s.pool.Raw().QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return out, identity.UnavailableError{}
	}
	out.Address, err = identity.NewIdentifierProjection(identity.IdentifierProjectionSpec{TenantID: q.TenantID, UserID: q.UserID, IdentifierID: identity.IdentifierID(q.RecordID), State: state, ObservedAt: at.UTC().Truncate(time.Microsecond), Values: identity.IdentifierValuesIncluded})
	if err != nil {
		return out, identity.UnavailableError{}
	}
	b, err := out.Address.Bindings()
	if err != nil || b.IdentifierVersion != receipt.Feature.AfterVersion || b.VerificationVersion != receipt.Feature.AfterVersion || out.Validate() != nil {
		return out, identity.UnavailableError{}
	}
	return out, nil
}

// VerificationRecover authorizes and observes only the exact original command.
// It accepts no proof/callback/execution input and returns no address or session.
// Unknown remains unknown; correlation never renews capability authority.
func (s *SignupService) VerificationRecover(ctx context.Context, request email.VerificationRecoveryRequest) (out email.VerificationRecoveryResult, err error) {
	if ctx == nil || request.Validate() != nil {
		return out, email.ErrInvalidVerification
	}
	q, _ := request.Recovery.Bindings()
	caller := request.Caller
	if caller.Request.Resource.ID == "" {
		caller.Request.Resource.ID = authorization.ResourceID(q.UserID)
	}
	receipt, err := s.RecoverRegistrationVerification(ctx, q, caller)
	if receipt.Outcome == identity.CommitOutcomeInvalid {
		return out, err
	}
	out = email.VerificationRecoveryResult{Outcome: receipt.Outcome, Recovery: request.Recovery, RetryAfter: receipt.RetryAfter}
	if out.Validate() != nil {
		return out, identity.UnavailableError{}
	}
	return out, err
}

func confirmationRecoveryQuery(receipt identity.CommandResult) identity.RecoveryQuery {
	b := receipt.Binding
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, RecordID: b.RecordID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID}
}
