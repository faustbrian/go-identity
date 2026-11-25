package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
)

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
	if code != FeatureFailureInvalidGroupMember && code != FeatureFailureConflict {
		return nil
	}
	if !c.owns(w) || w.usable() != nil {
		return invalidWork()
	}
	plan := w.state.execution.reservation.plan
	if plan.feature == nil || len(plan.audits) != 1 || plan.audits[0].EventType != scimBulkApplyChildAudit {
		return nil
	}
	entry, err := c.registry.selectFeatureOperation(*plan.feature)
	if err != nil || w.state.featureInvocation != nil {
		return w.fail(ctx, invalidWork())
	}
	owner, ok := entry.contributor.(SCIMBulkChildFailureContributor)
	if !ok {
		return nil // A previously compiled native adapter retains its original behavior.
	}
	w.state.scimBulkSkip = &scimBulkSkipPhase{}
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
