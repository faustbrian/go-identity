package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

type scimBulkUserMutationCase struct {
	name, operation, event, mismatchedEvent string
	before, after                           uint64
}

func scimBulkUserMutationCases() []scimBulkUserMutationCase {
	return []scimBulkUserMutationCase{
		{"replace", "identity.scim.user-replace", "identity.scim.user_replaced.v1", "identity.scim.user_patched.v1", 4, 5},
		{"changed-patch", "identity.scim.user-patch", "identity.scim.user_patched.v1", "identity.scim.user_patch_noop.v1", 4, 5},
		{"noop-patch", "identity.scim.user-patch", "identity.scim.user_patch_noop.v1", "identity.scim.user_patched.v1", 4, 4},
		{"delete", "identity.scim.user-delete", "identity.scim.user_deleted.v1", "identity.scim.user_replaced.v1", 4, 5},
	}
}

func scimBulkUserMutationPlan(t *testing.T, mutation scimBulkUserMutationCase) admittedKernelPlan {
	t.Helper()
	_, w, _ := scimBulkUserFailureFixture(t, scimUserUpdateOperation(mutation.operation))
	plan := *w.state.execution.reservation.plan
	plan.binding.PolicyID, plan.binding.PolicyVersion = "scope-policy", 1
	plan.lifecycle = &LifecyclePlan{EventType: mutation.event, BeforeVersion: mutation.before, AfterVersion: mutation.after}
	plan.audits = []AuditPlan{{EventType: scimBulkApplyChildAudit, RetentionClass: "protected",
		SchemaVersion: 1, RetentionPolicyVersion: 1, Required: true, RequiredRecordCount: 1,
		MaxRecordBytes: 16384, MaxAggregateBytes: 16384}}
	return plan
}

func TestSCIMBulkUserMutationAuditBindsOriginalChildAndParent(t *testing.T) {
	for _, mutation := range scimBulkUserMutationCases() {
		t.Run(mutation.name, func(t *testing.T) {
			for _, outcome := range []string{"committed", "denied"} {
				t.Run(outcome, func(t *testing.T) {
					plan := scimBulkUserMutationPlan(t, mutation)
					records, err := featureMutationAudits(t.Context(), &plan, time.Unix(1700000000, 0).UTC(), outcome)
					if err != nil || len(records) != 1 {
						t.Fatal("native User mutation did not generate its protected child audit", err)
					}
					record := records[0]
					child := string(plan.binding.CommandID)
					if record.Action() != scimBulkApplyChildAudit || record.Subject().Type() != "scim_bulk_child" || record.Subject().ID() != child ||
						record.Context().CorrelationID() != plan.binding.CorrelationID || record.Attributes()["aggregate.id"] != child ||
						record.Attributes()["aggregate.type"] != "scim_bulk_child" || record.Attributes()["retention.class"] != "protected" {
						t.Fatal("User child audit changed the original child, parent or protected retention")
					}
					if digest, err := FeatureAuditBindingDigest(plan.binding, plan.feature.Operation, plan.subjectType, record); err != nil || digest == ([32]byte{}) {
						t.Fatal("User child audit did not bind to its original native command", err)
					}
					for _, scope := range []string{"child", "parent"} {
						binding := plan.binding
						foreign, err := identity.NewCommandID()
						if err != nil {
							t.Fatal(err)
						}
						if scope == "child" {
							binding.CommandID = foreign
						} else {
							binding.CorrelationID = string(foreign)
						}
						if _, err := FeatureAuditBindingDigest(binding, plan.feature.Operation, plan.subjectType, record); err == nil {
							t.Fatalf("User child audit bound to a borrowed %s", scope)
						}
					}
				})
			}
		})
	}
}

func TestSCIMBulkUserMutationAuditRejectsBorrowedScopes(t *testing.T) {
	for _, mutation := range scimBulkUserMutationCases() {
		t.Run(mutation.name, func(t *testing.T) {
			for _, mismatch := range []struct {
				name   string
				change func(*admittedKernelPlan)
			}{
				{"owner", func(p *admittedKernelPlan) { p.feature.Operation.Owner = "other" }},
				{"schema", func(p *admittedKernelPlan) { p.feature.Operation.SchemaID += ".other" }},
				{"schema-version", func(p *admittedKernelPlan) { p.feature.Operation.SchemaVersion++ }},
				{"record-requirement", func(p *admittedKernelPlan) { p.feature.Operation.RecordRequirement = identity.FeatureRecordOmitted }},
				{"version-policy", func(p *admittedKernelPlan) {
					if p.feature.Operation.VersionPolicy == identity.FeatureVersionSequential {
						p.feature.Operation.VersionPolicy = identity.FeatureVersionSequentialOrUnchanged
					} else {
						p.feature.Operation.VersionPolicy = identity.FeatureVersionSequential
					}
				}},
				{"subject", func(p *admittedKernelPlan) { p.subjectType = "scim_group" }},
				{"invalid-parent", func(p *admittedKernelPlan) { p.binding.CorrelationID = "not-a-command" }},
				{"same-command-parent", func(p *admittedKernelPlan) { p.binding.CorrelationID = string(p.binding.CommandID) }},
				{"human-actor", func(p *admittedKernelPlan) { p.binding.ActorKind = authorization.SubjectUser }},
				{"non-scim-operation", func(p *admittedKernelPlan) { p.feature.Operation = apiKeyVerificationOperation(false) }},
			} {
				t.Run(mismatch.name, func(t *testing.T) {
					plan := scimBulkUserMutationPlan(t, mutation)
					mismatch.change(&plan)
					operation := plan.feature.Operation
					plan.binding.OperationID, plan.binding.SchemaID, plan.binding.SchemaVersion = operation.OperationID, operation.SchemaID, operation.SchemaVersion
					if _, _, err := featureAuditRecordScope(plan.binding, operation, plan.subjectType, scimBulkApplyChildAudit); err == nil {
						t.Fatal("borrowed User mutation scope acquired a Bulk child audit")
					}
				})
			}
		})
	}
}

func TestSCIMBulkUserMutationLifecycleKeepsOrdinaryUserTarget(t *testing.T) {
	for _, mutation := range scimBulkUserMutationCases() {
		t.Run(mutation.name, func(t *testing.T) {
			for _, event := range []string{mutation.event, "identity.scim.user_created.v1", mutation.mismatchedEvent} {
				t.Run(event, func(t *testing.T) {
					plan := scimBulkUserMutationPlan(t, mutation)
					plan.lifecycle.EventType = event
					now := time.Unix(1700000000, 0).UTC()
					records, err := featureMutationAudits(t.Context(), &plan, now, "committed")
					if err != nil || len(records) != 1 {
						t.Fatal("User child security event missing", err)
					}
					record := records[0]
					plan.audits[0].BindingDigest, err = FeatureAuditBindingDigest(plan.binding, plan.feature.Operation, plan.subjectType, record)
					if err != nil {
						t.Fatal(err)
					}
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
							t.Fatal("User child audit authorized a different User lifecycle event")
						}
						return
					}
					if err != nil || len(events) != 1 {
						t.Fatal("User child audit prevented the ordinary User lifecycle", err)
					}
					got := events[0]
					if got.CommandID != plan.binding.CommandID || got.TenantID != plan.binding.TenantID || got.UserID != plan.binding.UserID ||
						got.OperationID != mutation.operation || got.SubjectType != "scim_user" || got.SubjectID != plan.binding.RecordID ||
						got.EventType != mutation.event || got.BeforeVersion != mutation.before || got.AfterVersion != mutation.after || got.OccurredAt != now {
						t.Fatal("User child audit changed the ordinary User lifecycle identity or version transition")
					}
				})
			}
		})
	}
}
