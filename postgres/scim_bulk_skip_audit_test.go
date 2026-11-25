package postgres

import (
	"maps"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-audit"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestSCIMBulkSkipAuditsUseOnlyProtectedChildIdentities(t *testing.T) {
	commandID := func() identity.CommandID {
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	op := identity.FeatureOperation{Owner: "scim", OperationID: "identity.scim.group-create", SchemaID: "identity.scim.group-create.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	binding := identity.CommandBinding{CommandID: commandID(), TenantID: "tenant-a", ActorID: "scim-service", ActorKind: authorization.SubjectServiceAccount,
		PolicyID: "scope-policy", PolicyVersion: 1, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1,
		RecordID: "unrelated-group", CorrelationID: string(commandID())}
	children := []SCIMBulkSkippedChild{{CommandID: commandID(), Ordinal: 2}, {CommandID: commandID(), Ordinal: 999}}
	trigger := AuditPlan{RetentionPolicyVersion: 13, RetentionClass: "protected"}
	entries, err := makeSCIMBulkSkipAudits(t.Context(), binding, op, trigger, children, time.Now().UTC().Truncate(time.Microsecond))
	if err != nil || len(entries) != len(children) {
		t.Fatal("build one event per skipped child", err)
	}
	if entries[0].BindingDigest == ([32]byte{}) || entries[0].BindingDigest == entries[1].BindingDigest || entries[0].Record.ID() == entries[1].Record.ID() {
		t.Fatal("the retained child bindings and record IDs must remain distinct")
	}
	for i, entry := range entries {
		child := children[i]
		record := entry.Record
		actor, subject, scope := record.Actor(), record.Subject(), record.Context()
		wantAttributes := map[string]string{"identity.profile": "identity.security.v1", "retention.class": "protected", "command.id": string(child.CommandID),
			"scim.bulk.operation_order": strconv.FormatUint(uint64(child.Ordinal), 10)}
		if entry.Child != child || entry.RetentionPolicyVersion != trigger.RetentionPolicyVersion ||
			record.Action() != "identity.scim.bulk_skip_child" || record.Outcome() != audit.OutcomeDenied ||
			record.ReasonCode() != "identity.scim.fail_on_errors_cutoff" || !record.RedactionApplied() || !record.Changes().NoChange() || record.Description() != "" ||
			actor.Kind() != audit.ActorService || actor.ID() != string(binding.ActorID) || subject.Type() != "scim_bulk_child" || subject.ID() != string(child.CommandID) ||
			scope.TenantID() != string(binding.TenantID) || scope.CorrelationID() != binding.CorrelationID || scope.CausationID() != string(binding.CommandID) ||
			!maps.Equal(record.Attributes(), wantAttributes) {
			t.Fatal("cutoff event includes exactly its safe service, parent and child custody", i)
		}
	}
}
