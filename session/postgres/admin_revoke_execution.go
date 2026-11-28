package postgres

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// AdminRevokeExecutorConfig selects independent native admission policy for
// the ordinary password/TOTP actor and its original stored synchronizer key.
// Sessions must be the exact owned reader used by the admission service.
type AdminRevokeExecutorConfig struct {
	Execution IssueExecutorConfig
	Sessions  *session.SessionService
	Actor     IdentifierAdmissionConfig
	CSRFKey   session.CSRFKey
}

// AdminRevokeExecutor owns native single-target execution and outcome recovery.
// It borrows the primary pool, reuses the existing transaction/effect journal,
// starts no goroutines and is safe for concurrent use. Close borrowed
// dependencies only after all callers finish.
type AdminRevokeExecutor struct {
	config AdminRevokeExecutorConfig
	base   *IssueExecutor
}

var _ session.AdminRevokeExecutor = (*AdminRevokeExecutor)(nil)

// NewAdminRevokeExecutor configures single-session admin writes without IO.
// Apply the admin revocation journal expansion and validation before enabling
// the writer. No existing self-service operation is enabled or broadened.
func NewAdminRevokeExecutor(pool *database.Pool, c AdminRevokeExecutorConfig) (*AdminRevokeExecutor, error) {
	x := c.Execution
	actor := c.Actor
	if !c.Sessions.Configured() || c.CSRFKey.Version() == 0 || !actor.valid() || actor.AuthenticationMethod != "password" || actor.CredentialKind != identity.CredentialPassword || actor.CredentialOwner != "identity/password" || actor.GlobalAuthorityID != x.Profile.GlobalAuthorityID || actor.PolicyNamespace != x.Profile.PolicyNamespace || actor.Audience != x.Profile.Audience {
		return nil, session.ErrInvalidInput
	}
	if nilIssueDependency(x.Authorization) || nilIssueDependency(x.Clock) || !scopeID(x.PolicyID) || x.PolicyVersion == 0 || x.AuditRetentionVersion == 0 || x.Coordinator.MaximumDuration < time.Millisecond || x.Coordinator.MaximumDuration > 30*time.Second {
		return nil, session.ErrInvalidInput
	}
	native, err := NewRepository(pool, x.Repository)
	if err != nil {
		return nil, err
	}
	c.Execution.Coordinator = copyRevokeCoordinatorConfig(x.Coordinator)
	base, err := newAdminRevokeInvocation(c, native, session.AdminSessionRevocation{}, adminRevokeTarget{})
	if err != nil {
		return nil, err
	}
	return &AdminRevokeExecutor{config: c, base: base}, nil
}

func newAdminRevokeInvocation(c AdminRevokeExecutorConfig, native *Repository, req session.AdminSessionRevocation, target adminRevokeTarget) (*IssueExecutor, error) {
	x := c.Execution
	participant := &adminRevokeParticipant{Repository: native, sessions: c.Sessions, profile: c.Actor, request: req, csrf: c.CSRFKey, target: target}
	coordinator, registry, err := newSessionCoordinator(native.pool, x, participant)
	if err != nil {
		return nil, err
	}
	return &IssueExecutor{coordinator, registry, native, x.Authorization, x.Clock, x.PolicyID, x.PolicyVersion, x.AuditRetentionVersion, x.Coordinator.MaximumDuration}, nil
}

// ExecuteAdminSessionRevoke checks the current policy before reading the exact
// primary target. A missing, already revoked, or out-of-scope row is an
// authorized no-op, without journal, audit-success or lifecycle writes.
// Only the exact original actor permits the transition within Work.
func (e *AdminRevokeExecutor) ExecuteAdminSessionRevoke(ctx context.Context, req session.AdminSessionRevocation) (out session.AdminSessionRevokeResult, err error) {
	entered := false
	var b identity.CommandBinding
	defer func() {
		if recover() != nil {
			err = session.ErrUnavailable
			if entered {
				err = identity.UnknownCommitError{CommandID: b.CommandID}
			}
			out = session.AdminSessionRevokeResult{}
		}
	}()
	if ctx == nil || e == nil || e.base == nil {
		return out, session.ErrInvalidInput
	}
	b, ok := req.Binding()
	if !ok || b.PolicyID != e.base.policyID || b.PolicyVersion != e.base.policyVersion {
		return out, identity.ForbiddenError{}
	}
	if err := req.Validate(e.config.Sessions, e.base.clock.Now()); err != nil {
		return out, err
	}
	if _, err := selectRevokeCSRFKey(req.Caller(), req.CSRFToken(), []session.CSRFKey{e.config.CSRFKey}); err != nil {
		return out, err
	}
	actor, err := req.Caller().Bindings()
	if err != nil || actor.Audience != e.config.Actor.Audience {
		return out, identity.ForbiddenError{}
	}
	remember, err := actor.Remember.Bindings()
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	factor, err := req.Caller().MFAAuthentication().Bindings()
	if err != nil {
		return out, identity.ForbiddenError{}
	}
	// Cap Work to the original authentication and the selected fifteen-minute
	// M24 TOTP profile (session.PrepareAdminSessionRevoke). The late native
	// check also validates the core policy itself after effects are staged.
	deadline := earliestAdminRevokeDeadline(req.ValidUntil(), actor.Authentication.Proof.IssuedAt.Add(remember.FreshFor), factor.VerifiedAt.Add(15*time.Minute))
	bounded, stop, err := sessionPrimaryDeadline(ctx, e.base.native, e.base.maximumDuration, deadline)
	if err != nil {
		return out, err
	}
	defer stop()
	decision := authorization.DecisionContext{
		PolicyRevision: authorization.Revision(b.PolicyVersion), CorrelationID: b.CorrelationID,
		Request: authorization.Request{Tenant: authorization.TenantID(b.TenantID), Subject: authorization.Subject{ID: authorization.SubjectID(b.ActorID), Kind: authorization.SubjectUser}, Action: authorization.Action(b.OperationID), Resource: authorization.Resource{Type: "identity.user", ID: authorization.ResourceID(b.UserID)}},
	}
	if err = e.base.allow(bounded, decision); err != nil {
		return out, err
	}
	target, present, err := e.base.native.readAdminRevokeTarget(bounded, b, actor.Audience)
	if err != nil {
		return out, err
	}
	if err = req.Validate(e.config.Sessions, e.base.clock.Now()); err != nil {
		return out, err
	}
	if bounded.Err() != nil {
		return out, readError(bounded, bounded.Err())
	}
	if !present {
		return out, nil
	}
	owned, err := newAdminRevokeInvocation(e.config, e.base.native, req, target)
	if err != nil {
		return out, err
	}
	command, plan, err := planAdminRevoke(owned, b, target)
	if err != nil {
		return out, err
	}
	entered = true
	reservation, result, err := owned.coordinator.ReserveCommand(bounded, b, command, plan)
	if err != nil || reservation == (kernel.Reservation{}) {
		return adminRevokeCommitResult(b, target.version, result, err)
	}
	work, err := owned.coordinator.Begin(bounded, reservation)
	if err != nil {
		return out, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	defer owned.coordinator.Abort(work, identity.UnavailableError{})
	result, err = owned.coordinator.ApplyFeature(bounded, work, command)
	if err != nil {
		result, err = owned.coordinator.Abort(work, err)
		return adminRevokeCommitResult(b, target.version, result, err)
	}
	if err = req.Validate(e.config.Sessions, e.base.clock.Now()); err != nil {
		result, err = owned.coordinator.Abort(work, identity.ForbiddenError{})
		return adminRevokeCommitResult(b, target.version, result, err)
	}
	result, err = owned.coordinator.Commit(work, result)
	return adminRevokeCommitResult(b, target.version, result, err)
}

func earliestAdminRevokeDeadline(lease, primary, factor time.Time) time.Time {
	if primary.Before(lease) {
		lease = primary
	}
	if factor.Before(lease) {
		lease = factor
	}
	return lease
}

func adminRevokeCommitResult(b identity.CommandBinding, version uint64, r identity.CommandResult, err error) (session.AdminSessionRevokeResult, error) {
	if r.Outcome == identity.CommitOutcomeUnknown {
		return session.AdminSessionRevokeResult{}, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	if err != nil {
		return session.AdminSessionRevokeResult{}, err
	}
	if r.Binding != b || r.Outcome != identity.CommitOutcomeCommitted || r.Feature == nil || r.Feature.Operation != session.AdminSessionRevokeOperation() || r.Feature.BeforeVersion != version || r.Feature.AfterVersion != version+1 {
		return session.AdminSessionRevokeResult{}, identity.UnknownCommitError{CommandID: b.CommandID}
	}
	return session.AdminSessionRevokeResult{Revoked: true, Version: session.SessionVersion(r.Feature.AfterVersion)}, nil
}

func planAdminRevoke(owned *IssueExecutor, b identity.CommandBinding, target adminRevokeTarget) (identity.Command, kernel.CommandPlan, error) {
	command, err := mapAdminRevokeCommand(b, target)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	bld, err := audit.NewBuilder(audit.BuilderConfig{})
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, session.ErrUnavailable
	}
	op := session.AdminSessionRevokeOperation()
	transition := adminRevokeTransition(target.version)
	const retention = "protected"
	record, err := bld.Build(audit.RecordInput{
		OccurredAt: owned.clock.Now().UTC().Truncate(time.Microsecond), Action: op.OperationID, Outcome: audit.OutcomeSucceeded,
		Actor: audit.ActorInput{Kind: audit.ActorHuman, ID: string(b.ActorID)}, Subject: audit.SubjectInput{Type: "session", ID: b.RecordID},
		Context: audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID},
		Policy:  audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)}, Changes: audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"command.id": string(b.CommandID), "aggregate.id": b.RecordID, "aggregate.type": "session", "aggregate.before_version": strconv.FormatUint(transition.BeforeVersion, 10), "aggregate.after_version": strconv.FormatUint(transition.AfterVersion, 10), "retention.class": retention},
	})
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, session.ErrUnavailable
	}
	digest, err := kernel.FeatureAuditBindingDigest(b, op, "session", record)
	if err != nil {
		return identity.Command{}, kernel.CommandPlan{}, err
	}
	declaration := kernel.CommandPlan{
		Contributors: owned.registry.Descriptors(), SubjectType: "session", Feature: &kernel.FeatureRegistration{Contributor: owned.native.Descriptor(), Operation: op}, Lifecycle: &transition,
		Audits: []kernel.AuditPlan{{EventType: op.OperationID, SchemaVersion: 1, BindingDigest: digest, RetentionClass: retention, RetentionPolicyVersion: owned.retentionVersion, RequiredRecordCount: 1, MaxRecordBytes: 16384, MaxAggregateBytes: 16384, Required: true}},
	}
	plan, err := owned.coordinator.PrepareCommandPlan(b, command, declaration)
	return command, plan, err
}

// RecoverAdminSessionRevoke reuses the existing exact command recovery owner.
// The caller must come from current trusted authentication and match the
// original actor, tenant, operation and target authorization. The result is
// historical transition evidence, not permission or a refreshed session.
func (e *AdminRevokeExecutor) RecoverAdminSessionRevoke(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || e == nil || e.base == nil {
		return identity.CommandResult{}, session.ErrInvalidInput
	}
	if q.OperationID != session.AdminSessionRevokeOperation().OperationID || q.ActorKind != authorization.SubjectUser || q.ActorID == "" || q.UserID == "" || !scopeID(q.RecordID) || q.LinkMode != 0 || q.AnonymousFlowID != "" {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	return e.base.coordinator.RecoverFeatureCommand(ctx, q, caller)
}

// Format redacts borrowed configuration and credential-key policy.
func (AdminRevokeExecutor) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AdminRevokeExecutor(redacted)"))
}

// MarshalJSON rejects hidden configuration export.
func (AdminRevokeExecutor) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }
