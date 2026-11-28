package impersonationpostgres

import (
	"context"
	"errors"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/impersonation"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Execute reserves and applies the exact prepared command. No success
// receipt is returned before commit. Always check the receipt Outcome:
// a replay can return the retained NotCommitted receipt with nil error.
// Recover the original Binding instead of repeating an uncertain operation.
func (s *Service) Execute(ctx context.Context, input PreparedCommand) (identity.CommandResult, error) {
	p := input.state
	if s == nil || ctx == nil || p == nil || p.owner != s || p.phase == nil || p.coordinator == nil {
		return identity.CommandResult{}, impersonation.ErrInvalidInput
	}
	bounded, stop := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer stop()
	phase := p.phase
	b := phase.binding
	scope := phase.original.request.Scope()
	requireOriginal := func(ctx context.Context) error {
		if phase.stop != nil {
			return phase.stop.checkPreparedStop(ctx, s, b)
		}
		return s.requireActor(ctx, phase.actor.input, b)
	}
	if err := requireOriginal(bounded); err != nil {
		return identity.CommandResult{}, err
	}
	if b.OperationID == stopAction {
		if err := s.authorizeStop(bounded, b); err != nil {
			return identity.CommandResult{}, err
		}
	} else if b.OperationID == revokeAction {
		if err := s.authorizeRevocation(bounded, b); err != nil {
			return identity.CommandResult{}, err
		}
	} else {
		if err := s.authorize(bounded, b, scope); err != nil {
			return identity.CommandResult{}, err
		}
	}
	if b.OperationID == approveAction {
		requester := s.originalRequesterBinding(phase.observed)
		if err := s.authorize(bounded, requester, scope); err != nil {
			return identity.CommandResult{}, err
		}
	}
	if b.OperationID == startAction {
		approval := phase.start.retained
		approver := s.binding(approveAction, approval.commandID, phase.observed.id, b.TenantID, approval.approver, b.UserID)
		if err := s.authorize(bounded, approver, scope); err != nil {
			return identity.CommandResult{}, err
		}
	}
	reserved, result, err := p.coordinator.ReserveCommand(bounded, b, phase.command, p.plan)
	if err != nil || reserved == (kernel.Reservation{}) {
		if result.Outcome != identity.CommitOutcomeInvalid {
			if authErr := requireOriginal(bounded); authErr != nil {
				return identity.CommandResult{}, authErr
			}
		}
		return result, err
	}
	work, err := p.coordinator.Begin(bounded, reserved)
	if err != nil {
		var uncertain identity.UnknownCommitError
		if errors.As(err, &uncertain) {
			op, _ := approvalOperation(b.OperationID)
			return identity.CommandResult{Binding: b, Outcome: identity.CommitOutcomeUnknown, Feature: &identity.FeatureReceipt{Operation: op}}, err
		}
		return identity.CommandResult{}, err
	}
	defer p.coordinator.Abort(work, identity.UnavailableError{})
	applied, err := p.coordinator.ApplyFeature(bounded, work, phase.command)
	if err != nil {
		result, err := p.coordinator.Abort(work, err)
		return bindConflict(b, result, err)
	}
	result, err = p.coordinator.Commit(work, applied)
	return bindConflict(b, result, err)
}

func bindConflict(original identity.CommandBinding, result identity.CommandResult, err error) (identity.CommandResult, error) {
	var conflict identity.ConflictError
	if result.Binding == original && result.Outcome == identity.CommitOutcomeNotCommitted && errors.As(err, &conflict) {
		err = identity.ConflictError{CommandID: original.CommandID}
	}
	return result, err
}

// Recover discloses or reconciles an exact original command for its currently
// authenticated original administrator. The current policy must separately
// allow a recovery request against the bound user (resource attributes
// identity.command.recovery and identity.command.id). It never retries approval
// or renews original evidence. Fresh credentials need not use the old session.
func (s *Service) Recover(ctx context.Context, auth Authentication, binding identity.CommandBinding) (identity.CommandResult, error) {
	if s == nil || ctx == nil {
		return identity.CommandResult{}, impersonation.ErrInvalidInput
	}
	op, selected := approvalOperation(binding.OperationID)
	_, err := identity.ParseCommandID(binding.RecordID)
	isOriginalRequest := string(binding.CommandID) == binding.RecordID
	if !selected || err != nil || binding.ValidateFor(op) != nil || (binding.OperationID == requestAction) != isOriginalRequest ||
		binding.ActorKind != authorization.SubjectUser || binding.CorrelationID != string(binding.CommandID) ||
		identity.UserID(binding.ActorID) == binding.UserID || binding.OperationID == startAction && s.activation == nil ||
		binding.OperationID == revokeAction && !s.revocation || binding.OperationID == stopAction {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	return s.recoverBound(ctx, binding, func(bounded context.Context) error {
		return s.requireActor(bounded, auth, binding)
	})
}

func (s *Service) recoverBound(ctx context.Context, binding identity.CommandBinding, requireOriginal func(context.Context) error) (identity.CommandResult, error) {
	op, _ := approvalOperation(binding.OperationID)
	bounded, stop := context.WithTimeout(ctx, s.config.Coordinator.MaximumDuration)
	defer stop()
	if err := requireOriginal(bounded); err != nil {
		return identity.CommandResult{}, err
	}
	coordinator, _, err := s.coordinator(&approvalPhase{service: s})
	if err != nil {
		return identity.CommandResult{}, err
	}
	caller := authorization.DecisionContext{
		PolicyRevision: authorization.Revision(s.config.Policy.Version()), CorrelationID: binding.CorrelationID,
		Request: authorization.Request{
			Subject: authorization.Subject{Kind: binding.ActorKind, ID: authorization.SubjectID(binding.ActorID)},
			Action:  authorization.Action(binding.OperationID), Tenant: authorization.TenantID(binding.TenantID),
			Resource:    authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(binding.UserID)},
			Environment: authorization.Environment{Time: s.config.Session.Validation.Clock.Now().UTC()},
		},
	}
	query := identity.RecoveryQuery{CommandID: binding.CommandID, TenantID: binding.TenantID, UserID: binding.UserID,
		ActorID: binding.ActorID, ActorKind: binding.ActorKind, OperationID: binding.OperationID, RecordID: binding.RecordID}
	// The generic query selector omits historical policy/schema metadata. Check
	// the complete immutable binding before reconciliation can settle a lease.
	// Terminal classified errors still have a bound record; Recover restores
	// the full receipt below. Authorization always uses the current revision.
	observed, observationErr := coordinator.QueryCommand(bounded, query, caller)
	if observed.Outcome == identity.CommitOutcomeInvalid && observationErr != nil {
		return identity.CommandResult{}, observationErr
	}
	if observed.Binding != binding || observed.Feature == nil || *observed.Feature != op {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	result, err := coordinator.RecoverFeatureCommand(bounded, query, caller)
	if result.Outcome == identity.CommitOutcomeInvalid {
		return result, err
	}
	if result.Binding != binding || result.Feature == nil || result.Feature.Operation != op {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	if authErr := requireOriginal(bounded); authErr != nil {
		return identity.CommandResult{}, authErr
	}
	return result, err
}

func (s *Service) requireActor(ctx context.Context, auth Authentication, b identity.CommandBinding) error {
	if auth.Tenant != b.TenantID {
		return identity.ForbiddenError{}
	}
	actor, err := authenticateActor(ctx, s.sessions, s.config.Session, s.config.CSRFKey, auth)
	if err != nil {
		return err
	}
	spec, err := actor.observed.Session.Bindings()
	if err != nil || spec.UserID != identity.UserID(b.ActorID) {
		return identity.ForbiddenError{}
	}
	return nil
}
