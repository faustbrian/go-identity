package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type scimBulkGroupMutationCase struct {
	name, operation, event, mismatchedEvent string
	before, after                           uint64
}

func scimBulkGroupMutationCases() []scimBulkGroupMutationCase {
	return []scimBulkGroupMutationCase{
		{"replace", "identity.scim.group-replace", "identity.scim.group_replaced.v1", "identity.scim.group_patched.v1", 4, 5},
		{"changed-patch", "identity.scim.group-patch", "identity.scim.group_patched.v1", "identity.scim.group_patch_noop.v1", 4, 5},
		{"noop-patch", "identity.scim.group-patch", "identity.scim.group_patch_noop.v1", "identity.scim.group_patched.v1", 4, 4},
		{"delete", "identity.scim.group-delete", "identity.scim.group_deleted.v1", "identity.scim.group_replaced.v1", 4, 5},
	}
}

func scimBulkGroupMutationAuditPlan(t *testing.T, mutation scimBulkGroupMutationCase) admittedKernelPlan {
	t.Helper()
	child, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	operation := groupFailureOperation(mutation.operation)
	subject := featureFailureSubject(operation)
	if subject != "scim_group" {
		t.Fatal("fixture is not an exact native Group operation")
	}
	return admittedKernelPlan{
		binding: identity.CommandBinding{
			CommandID: child, TenantID: "tenant-a", UserID: "scim-service", ActorID: "scim-service",
			ActorKind: authorization.SubjectServiceAccount, OperationID: operation.OperationID,
			PolicyID: "scope-policy", PolicyVersion: 1, SchemaID: operation.SchemaID, SchemaVersion: operation.SchemaVersion,
			RecordID: "group-projection", CorrelationID: string(parent),
		},
		feature:     &FeatureRegistration{Operation: operation, Contributor: scimUserCreationDescriptor()},
		subjectType: subject,
		lifecycle:   &LifecyclePlan{EventType: mutation.event, BeforeVersion: mutation.before, AfterVersion: mutation.after},
		audits: []AuditPlan{{EventType: "identity.scim.bulk_apply_child", RetentionClass: "protected",
			SchemaVersion: 1, RetentionPolicyVersion: 1, Required: true, RequiredRecordCount: 1,
			MaxRecordBytes: 16384, MaxAggregateBytes: 16384}},
	}
}

func TestSCIMBulkGroupMutationAuditBindsOriginalChildAndParent(t *testing.T) {
	for _, mutation := range scimBulkGroupMutationCases() {
		t.Run(mutation.name, func(t *testing.T) {
			for _, outcome := range []string{"committed", "denied"} {
				t.Run(outcome, func(t *testing.T) {
					plan := scimBulkGroupMutationAuditPlan(t, mutation)
					records, err := featureMutationAudits(t.Context(), &plan, time.Unix(1700000000, 0).UTC(), outcome)
					if err != nil || len(records) != 1 {
						t.Fatal("native Group mutation did not generate its child security event", err)
					}
					record := records[0]
					child := string(plan.binding.CommandID)
					if record.Action() != "identity.scim.bulk_apply_child" || record.Subject().Type() != "scim_bulk_child" ||
						record.Subject().ID() != child || record.Context().CorrelationID() != plan.binding.CorrelationID ||
						record.Attributes()["command.id"] != child || record.Attributes()["aggregate.id"] != child ||
						record.Attributes()["aggregate.type"] != "scim_bulk_child" {
						t.Fatal("child audit changed the original child or parent identity")
					}
					digest, err := FeatureAuditBindingDigest(plan.binding, plan.feature.Operation, plan.subjectType, record)
					if err != nil || digest == ([32]byte{}) {
						t.Fatal("generated child event did not bind to the native Group command", err)
					}
					for _, foreignScope := range []string{"child", "parent"} {
						binding := plan.binding
						foreign, err := identity.NewCommandID()
						if err != nil {
							t.Fatal(err)
						}
						if foreignScope == "child" {
							binding.CommandID = foreign
						} else {
							binding.CorrelationID = string(foreign)
						}
						if _, err := FeatureAuditBindingDigest(binding, plan.feature.Operation, plan.subjectType, record); err == nil {
							t.Fatalf("child event bound to a different original %s", foreignScope)
						}
					}
				})
			}
		})
	}
}

func TestSCIMBulkGroupMutationLifecycleKeepsOrdinaryGroupTarget(t *testing.T) {
	for _, mutation := range scimBulkGroupMutationCases() {
		t.Run(mutation.name, func(t *testing.T) {
			for _, event := range []string{mutation.event, "identity.scim.group_created.v1", mutation.mismatchedEvent} {
				t.Run(event, func(t *testing.T) {
					plan := scimBulkGroupMutationAuditPlan(t, mutation)
					plan.lifecycle.EventType = event
					now := time.Unix(1700000000, 0).UTC()
					records, err := featureMutationAudits(t.Context(), &plan, now, "committed")
					if err != nil || len(records) != 1 {
						t.Fatal("child security event missing", err)
					}
					record := records[0]
					digest, err := FeatureAuditBindingDigest(plan.binding, plan.feature.Operation, plan.subjectType, record)
					if err != nil {
						t.Fatal("child security event cannot bind", err)
					}
					plan.audits[0].BindingDigest = digest
					w, _, _ := auditFixture(t)
					w.state.binding, w.state.feature, w.state.subjectType = plan.binding, plan.feature, plan.subjectType
					if err := bindAuditPlans(w, plan.audits); err != nil {
						t.Fatal(err)
					}
					if err := w.StageAudit(0, record); err != nil {
						t.Fatal(err)
					}
					if err := bindLifecyclePlan(w, plan.lifecycle); err != nil {
						t.Fatal(err)
					}
					if err := w.StageLifecycle(0, now); err != nil {
						t.Fatal(err)
					}
					events, err := w.StagedLifecycle()
					if event != mutation.event {
						if err == nil || events != nil {
							t.Fatal("child audit authorized a different Group lifecycle event")
						}
						return
					}
					if err != nil || len(events) != 1 {
						t.Fatal("child audit prevented the ordinary Group lifecycle", err)
					}
					got := events[0]
					if got.CommandID != plan.binding.CommandID || got.TenantID != plan.binding.TenantID ||
						got.OperationID != plan.binding.OperationID || got.SubjectType != "scim_group" || got.SubjectID != plan.binding.RecordID ||
						got.EventType != mutation.event || got.BeforeVersion != mutation.before || got.AfterVersion != mutation.after || got.OccurredAt != now {
						t.Fatal("child audit changed the ordinary Group lifecycle target or version transition")
					}
				})
			}
		})
	}
}

func TestSCIMBulkGroupMutationAuditRejectsDifferentSchema(t *testing.T) {
	for _, mutation := range scimBulkGroupMutationCases() {
		t.Run(mutation.name, func(t *testing.T) {
			plan := scimBulkGroupMutationAuditPlan(t, mutation)
			op := &plan.feature.Operation
			op.SchemaID = op.OperationID + ".native-v2"
			op.SchemaVersion = 2
			plan.binding.SchemaID, plan.binding.SchemaVersion = op.SchemaID, op.SchemaVersion
			if _, err := featureMutationAudits(t.Context(), &plan, time.Unix(1700000000, 0).UTC(), "committed"); err == nil {
				t.Fatal("another native schema acquired a Bulk child audit")
			}
		})
	}
}
