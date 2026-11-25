package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestSCIMBulkChildAuditUsesOnlyTheChildAndParentIdentities(t *testing.T) {
	child, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.group-create", SchemaID: "identity.scim.group-create.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	b := identity.CommandBinding{CommandID: child, TenantID: "tenant-a", UserID: "scim-service", ActorID: "scim-service",
		ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "scope-policy", PolicyVersion: 1,
		SchemaID: op.SchemaID, SchemaVersion: 1, RecordID: "group-projection", CorrelationID: string(parent)}
	plan := admittedKernelPlan{binding: b, feature: &FeatureRegistration{Operation: op, Contributor: scimUserCreationDescriptor()}, subjectType: "scim_group",
		lifecycle: &LifecyclePlan{EventType: "identity.scim.group_created.v1", BeforeVersion: 0, AfterVersion: 1},
		audits: []AuditPlan{{EventType: "identity.scim.bulk_apply_child", RetentionClass: "protected",
			SchemaVersion: 1, RetentionPolicyVersion: 1, Required: true, RequiredRecordCount: 1,
			MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}}
	for _, outcome := range []string{"committed", "denied"} {
		records, err := featureMutationAudits(t.Context(), &plan, time.Now().UTC().Truncate(time.Microsecond), outcome)
		if err != nil || len(records) != 1 {
			t.Fatal("child security event missing", err)
		}
		record := records[0]
		if record.Action() != "identity.scim.bulk_apply_child" || record.Subject().Type() != "scim_bulk_child" || record.Subject().ID() != string(child) ||
			record.Context().CorrelationID() != string(parent) || record.Attributes()["aggregate.id"] != string(child) {
			t.Fatal("security event disclosed the Group projection instead of identifying the original child")
		}
		digest, err := FeatureAuditBindingDigest(b, op, "scim_group", record)
		if err != nil {
			t.Fatal("generated child event did not match its ordinary projection command scope", err)
		}
		if outcome != "committed" {
			continue
		}
		w, _, _ := auditFixture(t)
		w.state.binding, w.state.feature, w.state.subjectType = b, plan.feature, plan.subjectType
		plan.audits[0].BindingDigest = digest
		if err := bindAuditPlans(w, plan.audits); err != nil {
			t.Fatal(err)
		}
		if err := w.StageAudit(0, record); err != nil {
			t.Fatal(err)
		}
		if err := bindLifecyclePlan(w, plan.lifecycle); err != nil {
			t.Fatal(err)
		}
		if err := w.StageLifecycle(0, record.OccurredAt()); err != nil {
			t.Fatal(err)
		}
		events, err := w.StagedLifecycle()
		if err != nil || len(events) != 1 || events[0].SubjectType != "scim_group" || events[0].SubjectID != b.RecordID || events[0].CommandID != child {
			t.Fatal("child audit prevented or changed the Group lifecycle event", err)
		}
	}
	plan.binding.CorrelationID = string(child)
	if _, err := featureMutationAudits(t.Context(), &plan, time.Now().UTC().Truncate(time.Microsecond), "committed"); err == nil {
		t.Fatal("ordinary create without a distinct original Bulk parent acquired a Bulk event")
	}
}
