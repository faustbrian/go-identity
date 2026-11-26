package postgres

import (
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestSCIMBulkChildAuditUsesOnlyTheChildAndParentIdentities(t *testing.T) {
	group := identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.group-create", SchemaID: "identity.scim.group-create.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	for _, profile := range []struct {
		name      string
		operation identity.FeatureOperation
		subject   string
		event     string
	}{
		{name: "group", operation: group, subject: "scim_group", event: "identity.scim.group_created.v1"},
		{name: "user", operation: scimUserCreationOperation(), subject: "scim_user", event: "identity.scim.user_created.v1"},
	} {
		t.Run(profile.name, func(t *testing.T) {
			testSCIMBulkChildAuditIdentities(t, profile.operation, profile.subject, profile.event)
		})
	}
}

func testSCIMBulkChildAuditIdentities(t *testing.T, op identity.FeatureOperation, subject, event string) {
	t.Helper()
	child, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	b := identity.CommandBinding{CommandID: child, TenantID: "tenant-a", UserID: "scim-service", ActorID: "scim-service",
		ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "scope-policy", PolicyVersion: 1,
		SchemaID: op.SchemaID, SchemaVersion: 1, RecordID: "resource-projection", CorrelationID: string(parent)}
	if subject == "scim_user" {
		b.UserID = "created-user"
	}
	plan := admittedKernelPlan{binding: b, feature: &FeatureRegistration{Operation: op, Contributor: scimUserCreationDescriptor()}, subjectType: subject,
		lifecycle: &LifecyclePlan{EventType: event, BeforeVersion: 0, AfterVersion: 1},
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
			record.Context().CorrelationID() != string(parent) || record.Attributes()["aggregate.id"] != string(child) ||
			record.Actor().ID() != "scim-service" || record.Attributes()["retention.class"] != "protected" {
			t.Fatal("security event disclosed the resource projection instead of identifying the original child")
		}
		digest, err := FeatureAuditBindingDigest(b, op, subject, record)
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
		if err != nil || len(events) != 1 || events[0].SubjectType != subject || events[0].SubjectID != b.RecordID || events[0].UserID != b.UserID || events[0].CommandID != child || events[0].EventType != event {
			t.Fatal("child audit prevented or changed the resource lifecycle event", err)
		}
		for _, mismatch := range []struct {
			name   string
			change func(*StagedLifecycle)
		}{
			{name: "subject", change: func(event *StagedLifecycle) { event.SubjectType = "other_projection" }},
			{name: "projection", change: func(event *StagedLifecycle) { event.SubjectID = "other-projection" }},
			{name: "event", change: func(event *StagedLifecycle) { event.EventType = "identity.scim.other_created.v1" }},
			{name: "command", change: func(event *StagedLifecycle) { event.CommandID = parent }},
		} {
			t.Run("lifecycle_rejects_"+mismatch.name, func(t *testing.T) {
				changed := events[0]
				mismatch.change(&changed)
				if lifecycleAuditSubjectMatches(w, &changed, record) {
					t.Fatal("child audit accepted a mismatched lifecycle")
				}
			})
		}
	}
	plan.binding.CorrelationID = string(child)
	if _, err := featureMutationAudits(t.Context(), &plan, time.Now().UTC().Truncate(time.Microsecond), "committed"); err == nil {
		t.Fatal("ordinary create without a distinct original Bulk parent acquired a Bulk event")
	}
	plan.audits[0].EventType = op.OperationID
	records, err := featureMutationAudits(t.Context(), &plan, time.Now().UTC().Truncate(time.Microsecond), "committed")
	if err != nil || len(records) != 1 {
		t.Fatal("ordinary create audit missing", err)
	}
	if records[0].Action() != op.OperationID || records[0].Subject().Type() != subject || records[0].Subject().ID() != b.RecordID || records[0].Context().CorrelationID() != string(child) {
		t.Fatal("ordinary create audit lost its projection or same-command correlation")
	}
	plan.audits[0].BindingDigest, err = FeatureAuditBindingDigest(plan.binding, op, subject, records[0])
	if err != nil {
		t.Fatal("ordinary create audit binding rejected", err)
	}
	w, _, _ := auditFixture(t)
	w.state.binding, w.state.feature, w.state.subjectType = plan.binding, plan.feature, subject
	if err := bindAuditPlans(w, plan.audits); err != nil {
		t.Fatal(err)
	}
	if err := w.StageAudit(0, records[0]); err != nil {
		t.Fatal(err)
	}
	if err := bindLifecyclePlan(w, plan.lifecycle); err != nil {
		t.Fatal(err)
	}
	if err := w.StageLifecycle(0, records[0].OccurredAt()); err != nil {
		t.Fatal(err)
	}
	events, err := w.StagedLifecycle()
	if err != nil || len(events) != 1 || events[0].SubjectType != subject || events[0].SubjectID != b.RecordID || events[0].EventType != event {
		t.Fatal("ordinary create lifecycle changed", err)
	}
}

func TestSCIMBulkUserChildAuditRejectsOtherProjectionScopes(t *testing.T) {
	child, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	parent, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for _, mismatch := range []struct {
		name   string
		change func(*identity.CommandBinding, *identity.FeatureOperation, *string)
	}{
		{name: "same_command_parent", change: func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *string) {
			b.CorrelationID = string(child)
		}},
		{name: "invalid_parent", change: func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *string) {
			b.CorrelationID = "not-a-command"
		}},
		{name: "group_projection", change: func(_ *identity.CommandBinding, _ *identity.FeatureOperation, subject *string) {
			*subject = "scim_group"
		}},
		{name: "user_update", change: func(_ *identity.CommandBinding, op *identity.FeatureOperation, _ *string) {
			*op = scimUserUpdateOperation("identity.scim.user-replace")
		}},
		{name: "other_owner", change: func(_ *identity.CommandBinding, op *identity.FeatureOperation, _ *string) { op.Owner = "other" }},
		{name: "other_schema", change: func(_ *identity.CommandBinding, op *identity.FeatureOperation, _ *string) {
			op.SchemaID = "identity.scim.user-create.other-v1"
		}},
		{name: "human_actor", change: func(b *identity.CommandBinding, _ *identity.FeatureOperation, _ *string) {
			b.ActorKind = authorization.SubjectUser
		}},
	} {
		t.Run(mismatch.name, func(t *testing.T) {
			op := scimUserCreationOperation()
			subject := "scim_user"
			b := identity.CommandBinding{CommandID: child, TenantID: "tenant-a", UserID: "scim-service", ActorID: "scim-service",
				ActorKind: authorization.SubjectServiceAccount, OperationID: op.OperationID, PolicyID: "scope-policy", PolicyVersion: 1,
				SchemaID: op.SchemaID, SchemaVersion: 1, RecordID: "user-projection", CorrelationID: string(parent)}
			mismatch.change(&b, &op, &subject)
			b.OperationID, b.SchemaID = op.OperationID, op.SchemaID
			plan := admittedKernelPlan{binding: b, feature: &FeatureRegistration{Operation: op, Contributor: scimUserCreationDescriptor()}, subjectType: subject,
				lifecycle: &LifecyclePlan{EventType: "identity.scim.user_created.v1", AfterVersion: 1},
				audits:    []AuditPlan{{EventType: scimBulkApplyChildAudit, RetentionClass: "protected"}}}
			if _, err := featureMutationAudits(t.Context(), &plan, time.Now().UTC().Truncate(time.Microsecond), "committed"); err == nil {
				t.Fatal("mismatched scope acquired a Bulk child audit")
			}
		})
	}
}
