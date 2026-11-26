package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// SCIMBulkDependencyCheckpointContributor is the selected native parent
// adapter. It may reconcile an original child's nonterminal dependency state
// or append its protected cutoff skip. It never terminalizes another command,
// begins resource execution, renews authority, or retains borrowed Work.
type SCIMBulkDependencyCheckpointContributor interface {
	SCIMBulkChildFailureContributor
	SCIMBulkDependencyCheckpointSelected() bool
	ReconcileSCIMBulkDependency(context.Context, Work) (changed bool, err error)
}

func (c *Coordinator) reconcileSCIMBulkDependency(ctx context.Context, tx pgx.Tx, plan *admittedKernelPlan, result identity.CommandResult) (changed bool, err error) {
	if !c.canonicalSCIMBulk || result.Outcome != identity.CommitOutcomeCommitted || plan.feature == nil ||
		plan.feature.Operation != scimBulkFeatureOperation() || plan.feature.Contributor != scimUserCreationDescriptor() ||
		plan.subjectType != "scim_bulk" || plan.binding.ActorKind != authorization.SubjectServiceAccount ||
		plan.binding.RecordID != string(plan.binding.CommandID) || plan.binding.CorrelationID != string(plan.binding.CommandID) ||
		result.Binding != plan.binding || result.Feature == nil || result.Feature.Operation != plan.feature.Operation ||
		plan.lifecycle == nil || plan.lifecycle.EventType != "identity.scim.bulk_admitted.v1" ||
		plan.lifecycle.BeforeVersion != 0 || plan.lifecycle.AfterVersion != 1 ||
		len(plan.audits) != 1 || plan.audits[0].RetentionClass != "protected" ||
		plan.audits[0].EventType != scimBulkAdmitAudit && plan.audits[0].EventType != scimBulkRequestRoute {
		return false, nil
	}
	entry, err := c.registry.selectFeatureOperation(*plan.feature)
	if err != nil {
		return false, err
	}
	owner, ok := entry.contributor.(SCIMBulkDependencyCheckpointContributor)
	if !ok {
		return false, nil
	}
	defer func() {
		if recover() != nil {
			changed, err = false, identity.UnavailableError{}
		}
	}()
	if !owner.SCIMBulkDependencyCheckpointSelected() {
		return false, nil
	}
	// The parent receipt is already locked. This Work carries neither a
	// reservation generation nor an execution/audit plane. Only its closed
	// cutoff event owner may contribute a new child audit on this path.
	bounded, cancel := context.WithCancel(ctx)
	w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, binding: plan.binding,
		feature: plan.feature, lifecycle: &workLifecycle{plan: *plan.lifecycle}, featureInvocation: owner,
		scimBulkSkip: &scimBulkSkipPhase{plan: plan}}}
	defer invalidateWork(w)
	changed, err = owner.ReconcileSCIMBulkDependency(bounded, w)
	if err != nil || w.usable() != nil || w.state.rows != nil || w.state.scimBulkSkip.written && !changed {
		return false, identity.UnavailableError{}
	}
	return changed, nil
}
