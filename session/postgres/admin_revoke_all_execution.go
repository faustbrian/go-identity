package postgres

import (
	"context"
	"errors"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

var _ session.AdminRevokeAllExecutor = (*AdminRevokeExecutor)(nil)

func (e *AdminRevokeExecutor) allInvocation(req session.AdminSessionRevocation) (*IssueExecutor, error) {
	native, c := e.base.native, e.config.Execution
	p := &adminRevokeAllParticipant{Repository: native, config: e.config, request: req}
	coordinator, registry, err := newSessionCoordinator(native.pool, c, p)
	if err != nil {
		return nil, err
	}
	return &IssueExecutor{coordinator, registry, native, c.Authorization, c.Clock, c.PolicyID, c.PolicyVersion, c.AuditRetentionVersion, c.Coordinator.MaximumDuration}, nil
}

// ExecuteAdminSessionRevokeAll revokes the target user's still-active session
// rows across audiences, not their account, API keys, or OAuth grants. Install
// AdminRevokeAllMigrationSource first. The session-only subject version advances
// even for zero rows. A completed exact native command returns its retained
// result; a distinct HTTP attempt supplies a new command identifier.
func (e *AdminRevokeExecutor) ExecuteAdminSessionRevokeAll(ctx context.Context, req session.AdminSessionRevocation) (out session.AdminSessionRevokeAllResult, err error) {
	var b identity.CommandBinding
	entered := false
	defer func() {
		if recover() != nil {
			out, err = session.AdminSessionRevokeAllResult{}, session.ErrUnavailable
			if entered {
				err = identity.UnknownCommitError{CommandID: b.CommandID}
			}
		}
	}()
	op := session.AdminSessionRevokeAllOperation()
	a, err := e.admitAdminRevocation(ctx, req, op)
	if err != nil {
		return out, err
	}
	defer a.cancel()
	b = a.binding
	if b.RecordID != string(b.UserID) {
		return out, identity.ForbiddenError{}
	}
	owned, err := e.allInvocation(req)
	if err != nil {
		return out, err
	}
	// Read authorization and exact correlation precede any retry decision. A
	// forbidden/missing observation is deliberately indistinguishable; if
	// that ID already names a foreign scope the shared reservation rejects it.
	query := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID}
	replayed, err := owned.coordinator.RecoverFeatureCommand(a.ctx, query, a.decision)
	var forbidden identity.ForbiddenError
	if !errors.As(err, &forbidden) || replayed.Binding.CommandID != "" {
		return e.retainedAdminRevokeAll(a.ctx, b, replayed, err)
	}
	before, err := readAdminRevokeAllVersion(a.ctx, owned.native.pool.Raw(), owned.native.schema, b.TenantID, b.UserID)
	if err != nil {
		return out, err
	}
	command, err := mapAdminRevokeAllCommand(b, before)
	if err != nil {
		return out, err
	}
	command, plan, err := planAdminRevocation(owned, command, b, op, "session_set", adminRevokeAllTransition(before))
	if err != nil {
		return out, err
	}
	if err := req.Validate(e.config.Sessions, e.base.clock.Now()); err != nil {
		return out, err
	}
	entered = true
	reservation, result, err := owned.coordinator.ReserveCommand(a.ctx, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return e.retainedAdminRevokeAll(a.ctx, b, result, err)
	}
	work, err := owned.coordinator.Begin(a.ctx, reservation)
	if err != nil {
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	defer owned.coordinator.Abort(work, identity.UnavailableError{})
	result, err = owned.coordinator.ApplyFeature(a.ctx, work, command)
	if err != nil {
		result, err = owned.coordinator.Abort(work, err)
		return e.retainedAdminRevokeAll(a.ctx, b, result, err)
	}
	result, err = owned.coordinator.Commit(work, result)
	return e.retainedAdminRevokeAll(a.ctx, b, result, err)
}

func (e *AdminRevokeExecutor) retainedAdminRevokeAll(ctx context.Context, b identity.CommandBinding, r identity.CommandResult, err error) (session.AdminSessionRevokeAllResult, error) {
	var out session.AdminSessionRevokeAllResult
	if r.Outcome == identity.CommitOutcomeUnknown {
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	if err != nil {
		return out, err
	}
	if r.Binding != b {
		return out, identity.ConflictError{}
	}
	if r.Outcome == identity.CommitOutcomeInProgress {
		return out, identity.InProgressError{CommandID: b.CommandID, RetryAfter: r.RetryAfter}
	}
	if r.Outcome != identity.CommitOutcomeCommitted || r.Feature == nil || r.Feature.Operation != session.AdminSessionRevokeAllOperation() || r.Feature.BeforeVersion == ^uint64(0) || r.Feature.AfterVersion != r.Feature.BeforeVersion+1 {
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	result, present, err := readAdminRevokeAllReceipt(ctx, e.base.native.pool.Raw(), e.base.native.schema, b, adminRevokeAllTransition(r.Feature.BeforeVersion))
	if err != nil || !present {
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	return result, nil
}

// AdminRevokeAllRecoveryResult contains the exact original command observation.
// Result is populated only for a confirmed committed receipt, and never
// recomputed from the current set of live sessions.
type AdminRevokeAllRecoveryResult struct {
	Command identity.CommandResult
	Result  session.AdminSessionRevokeAllResult
}

// RecoverAdminSessionRevokeAll observes the exact original bulk command under
// current trusted authorization. It does not revoke sessions or mint a new
// subject version. The caller must supply current authenticated authority.
func (e *AdminRevokeExecutor) RecoverAdminSessionRevokeAll(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (out AdminRevokeAllRecoveryResult, err error) {
	if ctx == nil || e == nil || e.base == nil {
		return out, session.ErrInvalidInput
	}
	if q.OperationID != session.AdminSessionRevokeAllOperation().OperationID || q.ActorKind != authorization.SubjectUser || q.ActorID == "" || q.UserID == "" || q.RecordID != string(q.UserID) || q.LinkMode != 0 || q.AnonymousFlowID != "" {
		return out, identity.ForbiddenError{}
	}
	owned, err := e.allInvocation(session.AdminSessionRevocation{})
	if err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, owned.maximumDuration)
	defer stop()
	out.Command, err = owned.coordinator.RecoverFeatureCommand(ctx, q, caller)
	if err != nil || out.Command.Outcome != identity.CommitOutcomeCommitted {
		return out, err
	}
	out.Result, err = e.retainedAdminRevokeAll(ctx, out.Command.Binding, out.Command, nil)
	return out, err
}
