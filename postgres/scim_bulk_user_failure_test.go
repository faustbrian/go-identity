package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type scimBulkUserFailureParticipant struct {
	scopeFeatureParticipant
	binding identity.CommandBinding
	code    FeatureFailureCode
	work    Work
}

func (*scimBulkUserFailureParticipant) Descriptor() ContributorDescriptor {
	return scimUserCreationDescriptor()
}

func (p *scimBulkUserFailureParticipant) RecordSCIMBulkChildFailure(_ context.Context, w Work, code FeatureFailureCode) error {
	binding, _, _, err := w.FeatureScope(p)
	if err != nil || w.state.scimBulkSkip == nil {
		return invalidWork()
	}
	p.binding, p.code, p.work = binding, code, w
	return nil
}

func scimBulkUserFailureFixture(t *testing.T, operation identity.FeatureOperation) (*Coordinator, Work, *scimBulkUserFailureParticipant) {
	t.Helper()
	child, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	p := &scimBulkUserFailureParticipant{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{operation}}}
	registry, err := NewContributorRegistry([]Contributor{p})
	if err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{registry: registry}
	plan := &admittedKernelPlan{
		binding: identity.CommandBinding{CommandID: child, TenantID: "tenant-a", UserID: "created-user", ActorID: "scim-service",
			ActorKind: authorization.SubjectServiceAccount, OperationID: operation.OperationID,
			SchemaID: operation.SchemaID, SchemaVersion: operation.SchemaVersion, RecordID: "user-projection", CorrelationID: string(parent)},
		feature:     &FeatureRegistration{Operation: operation, Contributor: p.Descriptor()},
		subjectType: featureFailureSubject(operation),
		lifecycle:   &LifecyclePlan{EventType: "identity.scim.user_created.v1", AfterVersion: 1},
		audits:      []AuditPlan{{EventType: scimBulkApplyChildAudit, RetentionClass: "protected"}},
	}
	reservation := &reservationState{coordinator: c, plan: plan}
	w := Work{state: &workState{ctx: t.Context(), binding: plan.binding, registry: registry.state, feature: plan.feature,
		subjectType: plan.subjectType, lifecycle: &workLifecycle{plan: *plan.lifecycle},
		execution: &domainExecution{coordinator: c, reservation: reservation}}}
	return c, w, p
}

func TestSCIMBulkUserUniquenessSelectsOnlyOriginalProtectedCreateChild(t *testing.T) {
	c, w, owner := scimBulkUserFailureFixture(t, scimUserCreationOperation())
	if err := c.recordSCIMBulkChildFailure(t.Context(), w, FeatureFailureUniqueness); err != nil {
		t.Fatal("original User-create uniqueness checkpoint failed", err)
	}
	if owner.code != FeatureFailureUniqueness || owner.binding != w.state.binding {
		t.Fatal("original User-create uniqueness denial did not reach its registered child checkpoint")
	}
	if _, _, _, err := owner.work.FeatureScope(owner); err == nil || w.state.scimBulkSkip != nil {
		t.Fatal("returned child checkpoint retained feature or cutoff authority")
	}
}

func TestSCIMBulkUserUniquenessRejectsOtherFailureScopes(t *testing.T) {
	for _, test := range []struct {
		name      string
		operation identity.FeatureOperation
		change    func(*admittedKernelPlan)
	}{
		{name: "ordinary_user_create", change: func(p *admittedKernelPlan) { p.audits[0].EventType = "identity.scim.user-create" }},
		{name: "user_replace", operation: scimUserUpdateOperation("identity.scim.user-replace")},
		{name: "user_patch", operation: scimUserUpdateOperation("identity.scim.user-patch")},
		{name: "user_delete", operation: scimUserUpdateOperation("identity.scim.user-delete")},
		{name: "group_create", operation: groupFailureOperation("identity.scim.group-create")},
		{name: "group_replace", operation: groupFailureOperation("identity.scim.group-replace")},
		{name: "wrong_subject", change: func(p *admittedKernelPlan) { p.subjectType = "user" }},
		{name: "wrong_owner", change: func(p *admittedKernelPlan) { p.feature.Operation.Owner = "other" }},
		{name: "wrong_schema", change: func(p *admittedKernelPlan) { p.feature.Operation.SchemaID = "identity.scim.user-create.other-v1" }},
		{name: "wrong_contributor", change: func(p *admittedKernelPlan) { p.feature.Contributor.ContractID = "other" }},
		{name: "unprotected_audit", change: func(p *admittedKernelPlan) { p.audits[0].RetentionClass = "ordinary" }},
		{name: "invalid_parent", change: func(p *admittedKernelPlan) { p.binding.CorrelationID = "not-a-command" }},
		{name: "same_command_parent", change: func(p *admittedKernelPlan) { p.binding.CorrelationID = string(p.binding.CommandID) }},
		{name: "human_actor", change: func(p *admittedKernelPlan) { p.binding.ActorKind = authorization.SubjectUser }},
	} {
		t.Run(test.name, func(t *testing.T) {
			operation := test.operation
			if operation == (identity.FeatureOperation{}) {
				operation = scimUserCreationOperation()
			}
			c, w, owner := scimBulkUserFailureFixture(t, operation)
			plan := w.state.execution.reservation.plan
			if test.change != nil {
				test.change(plan)
			}
			w.state.binding, w.state.subjectType = plan.binding, plan.subjectType
			_ = c.recordSCIMBulkChildFailure(t.Context(), w, FeatureFailureUniqueness)
			if owner.code != 0 || owner.work.state != nil || w.state.scimBulkSkip != nil || w.state.featureInvocation != nil {
				t.Fatal("out-of-scope uniqueness denial acquired a native child checkpoint or cutoff authority")
			}
		})
	}
}
