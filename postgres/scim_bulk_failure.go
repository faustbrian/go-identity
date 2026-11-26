package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const scimBulkDenialProfile = "identity-scim-bulk-denial-v1"

func scimBulkDenialCode(code FeatureFailureCode) bool {
	return code == FeatureFailureGroupMissing || code == FeatureFailureGroupVersionRequired || code == FeatureFailureSCIMBulkDependency
}

func scimBulkGroupMutation(op identity.FeatureOperation) bool {
	return featureFailureSubject(op) == "scim_group" && op.OperationID != "identity.scim.group-create"
}

func validSCIMBulkDenialPlan(b identity.CommandBinding, p CommandPlan) bool {
	parent, err := identity.ParseCommandID(b.CorrelationID)
	return scimBulkDenialCode(p.SCIMBulkDenial) && p.Feature != nil && featureFailureCodeAllowed(p.Feature.Operation, p.SCIMBulkDenial) &&
		p.Feature.Contributor == scimUserCreationDescriptor() && p.SubjectType == "scim_group" &&
		b.ActorKind == authorization.SubjectServiceAccount && err == nil && parent != b.CommandID &&
		p.Lifecycle == nil && len(p.Audits) == 1 && p.Audits[0].EventType == scimBulkApplyChildAudit && p.Audits[0].RetentionClass == "protected" &&
		p.Capability == nil && p.CapabilityIssuance == nil && p.Delivery == nil && p.OTP == nil && p.RiskEvidence == nil &&
		p.CommandCounters == nil && p.CaptchaEvidence == nil && !p.CaptchaReplayReservation && p.IdentifierAdmission == nil &&
		p.AccountLinkState == nil && p.SCIMUserUpdate == nil && p.APIKeyVerification == nil && p.OrganizationInvitationOrigin == nil &&
		p.MFACompletion == nil && p.MFAContinuation == nil && p.MagicLinkRegistration == nil && p.PasskeyRegistration == nil &&
		!p.SignupAcceptance && !p.MagicLinkRequestAcceptance
}

// SCIMBulkChildFailureContributor records a definitive native Bulk child denial
// in the same transaction as its original failure audit and terminal receipt.
// It is only invoked for the exact registered Bulk child after proven rollback.
// Work authorizes the checkpoint, not another projection attempt. The owner
// must not close or retain Work, acquire new authority, or perform external I/O.
// A failure rolls back the terminal transaction; uncertainty is not a denial.
type SCIMBulkChildFailureContributor interface {
	FeatureExecutionContributor
	RecordSCIMBulkChildFailure(context.Context, Work, FeatureFailureCode) error
}

// SCIMBulkChildUnavailableContributor settles a started acyclic child's
// definitive dependency failure. It runs inside the fenced terminal transaction
// after proven rollback and must not attempt the original mutation again.
type SCIMBulkChildUnavailableContributor interface {
	SCIMBulkChildFailureContributor
	RecordSCIMBulkChildUnavailable(context.Context, Work) error
}

// MarkSCIMBulkChildStarted records invocation-local custody after the native
// adapter's acyclic start CAS succeeds. It grants no mutation authority and
// cannot settle an unknown outcome, cancelled attempt, or typed denial.
func (w Work) MarkSCIMBulkChildStarted(ctx context.Context, owner SCIMBulkChildUnavailableContributor, command identity.Command) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	if w.state.execution == nil || w.state.execution.reservation == nil || w.state.execution.component ||
		!w.state.featureApplying || w.state.scimBulkChildStarted || !scimBulkUnavailablePlan(w.state.execution.reservation.plan) {
		return w.fail(ctx, invalidWork())
	}
	w.state.scimBulkChildStarted = true
	return nil
}

func scimBulkUnavailablePlan(plan *admittedKernelPlan) bool {
	if plan == nil || plan.feature == nil || plan.lifecycle == nil || plan.scimBulkDenial != 0 ||
		plan.feature.Contributor != scimUserCreationDescriptor() || len(plan.audits) != 1 ||
		plan.audits[0].EventType != scimBulkApplyChildAudit || plan.audits[0].RetentionClass != "protected" {
		return false
	}
	operation := plan.feature.Operation
	if plan.binding.OperationID != operation.OperationID || plan.binding.SchemaID != operation.SchemaID ||
		plan.binding.SchemaVersion != operation.SchemaVersion || plan.binding.RecordID == "" {
		return false
	}
	_, _, err := featureAuditRecordScope(plan.binding, operation, plan.subjectType, scimBulkApplyChildAudit)
	return err == nil
}

func (c *Coordinator) recordSCIMBulkChildUnavailable(ctx context.Context, w Work) error {
	if !c.owns(w) || w.usable() != nil {
		return invalidWork()
	}
	plan := w.state.execution.reservation.plan
	if !scimBulkUnavailablePlan(plan) {
		return w.fail(ctx, invalidPlan())
	}
	entry, err := c.registry.selectFeatureOperation(*plan.feature)
	if err != nil || w.state.featureInvocation != nil {
		return w.fail(ctx, invalidWork())
	}
	owner, ok := entry.contributor.(SCIMBulkChildUnavailableContributor)
	if !ok {
		return w.fail(ctx, invalidWork())
	}
	return w.callSCIMBulkChildFailureOwner(ctx, owner, func() error { return owner.RecordSCIMBulkChildUnavailable(ctx, w) })
}

func (c *Coordinator) recordSCIMBulkChildFailure(ctx context.Context, w Work, code FeatureFailureCode) (err error) {
	if code != FeatureFailureUniqueness && code != FeatureFailureInvalidGroupMember && code != FeatureFailureConflict && code != FeatureFailurePrecondition && !scimBulkDenialCode(code) {
		return nil
	}
	if !c.owns(w) || w.usable() != nil {
		return invalidWork()
	}
	plan := w.state.execution.reservation.plan
	if plan.feature == nil || len(plan.audits) != 1 || plan.audits[0].EventType != scimBulkApplyChildAudit {
		return nil
	}
	// Only the original protected native User-create child may retain its
	// uniqueness denial; ordinary User commands and Group conflicts do not
	// acquire this checkpoint or its failOnErrors cutoff authority.
	if code == FeatureFailureUniqueness {
		if plan.feature.Operation != scimUserCreationOperation() || plan.feature.Contributor != scimUserCreationDescriptor() ||
			plan.subjectType != "scim_user" || plan.audits[0].RetentionClass != "protected" {
			return nil
		}
		if _, _, err := featureAuditRecordScope(plan.binding, plan.feature.Operation, plan.subjectType, scimBulkApplyChildAudit); err != nil {
			return nil
		}
	}
	// A Group create has no version precondition. Only the precise registered
	// mutation tuples may turn 412 into a terminal Bulk child checkpoint.
	if code == FeatureFailurePrecondition && !scimBulkGroupMutation(plan.feature.Operation) {
		return nil
	}
	if scimBulkDenialCode(code) && plan.scimBulkDenial != code {
		return w.fail(ctx, invalidPlan())
	}
	entry, err := c.registry.selectFeatureOperation(*plan.feature)
	if err != nil || w.state.featureInvocation != nil {
		return w.fail(ctx, invalidWork())
	}
	owner, ok := entry.contributor.(SCIMBulkChildFailureContributor)
	if !ok {
		if plan.scimBulkDenial != 0 {
			return w.fail(ctx, invalidPlan())
		}
		return nil // A previously compiled native adapter retains its original behavior.
	}
	return w.callSCIMBulkChildFailureOwner(ctx, owner, func() error { return owner.RecordSCIMBulkChildFailure(ctx, w, code) })
}

func (w Work) callSCIMBulkChildFailureOwner(ctx context.Context, owner SCIMBulkChildFailureContributor, record func() error) (err error) {
	w.state.scimBulkSkip = &scimBulkSkipPhase{plan: w.state.execution.reservation.plan}
	w.state.featureInvocation = owner
	defer func() {
		w.state.featureInvocation = nil
		w.state.scimBulkSkip = nil
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if err := record(); err != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	w.state.featureInvocation = nil
	if w.state.rows != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.usable()
}
