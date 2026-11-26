package postgres

import (
	"context"
	"strconv"

	"github.com/faustbrian/go-audit"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// SCIMBulkChildReconciler projects an exact prior Group Bulk denial, without
// reapplying it or extending its original authority. Return true only when the
// checkpoint changed and false only for an exact already-projected denial.
// Use current source authority. The last check runs after all protected writes.
type SCIMBulkChildReconciler interface {
	SCIMBulkChildFailureContributor
	ReconcileSCIMBulkChildFailure(context.Context, Work, FeatureFailureCode) (changed bool, err error)
	CheckSCIMBulkChildReconciliation(context.Context, Work) error
}

// SCIMBulkReconciliationAuditContributor appends the staged reconciliation
// event without changing the original command audit binding or closing Work.
type SCIMBulkReconciliationAuditContributor interface {
	AuditContributor
	PersistSCIMBulkReconciliationAudit(context.Context, Work) error
}

type scimBulkReconciliationAudit struct {
	owner  SCIMBulkReconciliationAuditContributor
	record audit.Record
}

// StagedSCIMBulkReconciliationAudit returns an immutable event only during the
// exact registered audit owner's reconciliation persistence callback.
func (w Work) StagedSCIMBulkReconciliationAudit(owner SCIMBulkReconciliationAuditContributor) (audit.Record, error) {
	if w.usable() != nil || w.state.scimBulkReconciliation == nil || !sameParticipant(w.state.scimBulkReconciliation.owner, owner) {
		return audit.Record{}, invalidWork()
	}
	return w.state.scimBulkReconciliation.record, nil
}

func (c *Coordinator) reconcileSCIMBulkChildFailure(ctx context.Context, tx pgx.Tx, plan *admittedKernelPlan, result identity.CommandResult, code FeatureFailureCode) (changed bool, err error) {
	if (code != FeatureFailureInvalidGroupMember && code != FeatureFailureConflict) || result.Outcome != identity.CommitOutcomeNotCommitted ||
		plan.feature == nil || plan.lifecycle == nil || len(plan.audits) != 1 || plan.audits[0].EventType != scimBulkApplyChildAudit ||
		plan.audits[0].RetentionClass != "protected" {
		return false, nil
	}
	if result.Binding != plan.binding || result.Feature == nil || result.Feature.Operation != plan.feature.Operation {
		return false, invalidWork()
	}
	entry, err := c.registry.selectFeatureOperation(*plan.feature)
	if err != nil {
		return false, err
	}
	owner, supported := entry.contributor.(SCIMBulkChildReconciler)
	if !supported {
		return false, nil // Previously compiled adapters retain their terminal read behavior.
	}
	// The original claim and terminal row are already locked. This capability
	// has no pending generation, execution state or normal audit staging plane.
	// It cannot be passed to Coordinator.ApplyFeature, Commit or Abort.
	bounded, cancel := context.WithCancel(ctx)
	w := Work{state: &workState{ctx: bounded, cancel: cancel, tx: tx, binding: plan.binding,
		feature: plan.feature, lifecycle: &workLifecycle{plan: *plan.lifecycle}, featureInvocation: owner,
		scimBulkSkip: &scimBulkSkipPhase{plan: plan}}}
	defer func() {
		invalidateWork(w)
		if recover() != nil {
			changed, err = false, identity.UnavailableError{}
		}
	}()
	changed, err = owner.ReconcileSCIMBulkChildFailure(bounded, w, code)
	if err != nil || w.usable() != nil || w.state.rows != nil {
		return false, identity.UnavailableError{}
	}
	if !changed {
		return false, nil
	}
	w.state.featureInvocation = nil
	if err := persistSCIMBulkReconciliationAudit(bounded, w, plan); err != nil {
		return false, identity.UnavailableError{}
	}
	w.state.featureInvocation = owner
	if err := owner.CheckSCIMBulkChildReconciliation(bounded, w); err != nil || w.usable() != nil || w.state.rows != nil {
		return false, identity.UnavailableError{}
	}
	return true, nil
}

func persistSCIMBulkReconciliationAudit(ctx context.Context, w Work, plan *admittedKernelPlan) error {
	var owner SCIMBulkReconciliationAuditContributor
	for _, entry := range plan.contributors {
		if entry.descriptor.Owner == "audit/postgres" {
			owner, _ = entry.contributor.(SCIMBulkReconciliationAuditContributor)
			break
		}
	}
	if owner == nil {
		return invalidAudit()
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	b := plan.binding
	builder, err := audit.NewBuilder(audit.BuilderConfig{Limits: securityAuditLimits(), IDGenerator: func() (string, error) {
		id, err := identity.NewSubjectID()
		return string(id), err
	}})
	if err != nil {
		return invalidAudit()
	}
	record, err := builder.Build(audit.RecordInput{
		OccurredAt: now, Action: "identity.scim.reconcile", Outcome: audit.OutcomeSucceeded, ReasonCode: "completed",
		Actor:      audit.ActorInput{Kind: audit.ActorSystem, ID: "scim-bulk-reconciler"},
		Subject:    audit.SubjectInput{Type: "scim_bulk_child", ID: string(b.CommandID)},
		Context:    audit.ContextInput{TenantID: string(b.TenantID), CorrelationID: b.CorrelationID, CausationID: string(b.CommandID)},
		Policy:     audit.PolicyMetadata{PolicyID: b.PolicyID, Version: strconv.FormatUint(b.PolicyVersion, 10)},
		Changes:    audit.ChangeSetInput{Redacted: true},
		Attributes: map[string]string{"identity.profile": "identity.security.v1", "command.id": string(b.CommandID), "retention.class": "protected"},
	})
	if err != nil {
		return invalidAudit()
	}
	redactor, err := audit.NewRedactor(audit.RedactionRules{DropDescription: true, DropNetworkOrigin: true, DropUserAgent: true,
		AllowedAttributes: []string{"identity.profile", "command.id", "retention.class"}})
	if err != nil {
		return invalidAudit()
	}
	record, err = redactor.Redact(ctx, record)
	if err != nil || !record.RedactionApplied() {
		return invalidAudit()
	}
	w.state.scimBulkReconciliation = &scimBulkReconciliationAudit{owner: owner, record: record}
	defer func() { w.state.scimBulkReconciliation = nil }()
	if err := owner.PersistSCIMBulkReconciliationAudit(ctx, w); err != nil || w.usable() != nil || w.state.rows != nil {
		return invalidAudit()
	}
	return nil
}
