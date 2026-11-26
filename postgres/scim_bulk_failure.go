package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

const scimBulkDenialProfile = "identity-scim-bulk-denial-v1"

func scimBulkDenialCode(code FeatureFailureCode) bool {
	return code == FeatureFailureGroupMissing || code == FeatureFailureGroupVersionRequired
}

func scimBulkGroupMutation(op identity.FeatureOperation) bool {
	return featureFailureSubject(op) == "scim_group" && op.OperationID != "identity.scim.group-create"
}

func validSCIMBulkDenialPlan(b identity.CommandBinding, p CommandPlan) bool {
	parent, err := identity.ParseCommandID(b.CorrelationID)
	return scimBulkDenialCode(p.SCIMBulkDenial) && p.Feature != nil && scimBulkGroupMutation(p.Feature.Operation) &&
		p.Feature.Contributor == scimUserCreationDescriptor() && p.SubjectType == "scim_group" &&
		b.ActorKind == authorization.SubjectServiceAccount && err == nil && parent != b.CommandID &&
		p.Lifecycle == nil && len(p.Audits) == 1 && p.Audits[0].EventType == scimBulkApplyChildAudit && p.Audits[0].RetentionClass == "protected" &&
		p.Capability == nil && p.CapabilityIssuance == nil && p.Delivery == nil && p.OTP == nil && p.RiskEvidence == nil &&
		p.CommandCounters == nil && p.CaptchaEvidence == nil && !p.CaptchaReplayReservation && p.IdentifierAdmission == nil &&
		p.AccountLinkState == nil && p.SCIMUserUpdate == nil && p.APIKeyVerification == nil && p.OrganizationInvitationOrigin == nil &&
		p.MFACompletion == nil && p.MFAContinuation == nil && p.MagicLinkRegistration == nil && p.PasskeyRegistration == nil &&
		!p.SignupAcceptance && !p.MagicLinkRequestAcceptance
}

// SCIMBulkChildFailureContributor records a definitive native Group Bulk denial
// in the same transaction as its original failure audit and terminal receipt.
// It is only invoked for the exact registered Bulk child after proven rollback.
// Work authorizes the checkpoint, not another projection attempt. The owner
// must not close or retain Work, acquire new authority, or perform external I/O.
// A failure rolls back the terminal transaction; uncertainty is not a denial.
type SCIMBulkChildFailureContributor interface {
	FeatureExecutionContributor
	RecordSCIMBulkChildFailure(context.Context, Work, FeatureFailureCode) error
}

func (c *Coordinator) recordSCIMBulkChildFailure(ctx context.Context, w Work, code FeatureFailureCode) (err error) {
	if code != FeatureFailureInvalidGroupMember && code != FeatureFailureConflict && code != FeatureFailurePrecondition && !scimBulkDenialCode(code) {
		return nil
	}
	if !c.owns(w) || w.usable() != nil {
		return invalidWork()
	}
	plan := w.state.execution.reservation.plan
	if plan.feature == nil || len(plan.audits) != 1 || plan.audits[0].EventType != scimBulkApplyChildAudit {
		return nil
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
	w.state.scimBulkSkip = &scimBulkSkipPhase{plan: plan}
	w.state.featureInvocation = owner
	defer func() {
		w.state.featureInvocation = nil
		w.state.scimBulkSkip = nil
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if err := owner.RecordSCIMBulkChildFailure(ctx, w, code); err != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	w.state.featureInvocation = nil
	if w.state.rows != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.usable()
}
