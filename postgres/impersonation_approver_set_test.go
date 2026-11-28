package postgres

import (
	"slices"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
)

func TestImpersonationApproverSetMatchesExactOriginalStart(t *testing.T) {
	newID := func() identity.CommandID {
		t.Helper()
		id, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: "identity.impersonation.start",
		SchemaID: "impersonation-start", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	registration := FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}, Operation: op}
	b := identity.CommandBinding{CommandID: newID(), TenantID: "tenant", UserID: "target", ActorID: "requester",
		ActorKind: authorization.SubjectUser, OperationID: op.OperationID, RecordID: string(newID()),
		PolicyID: "administration", PolicyVersion: 1, SchemaID: op.SchemaID, SchemaVersion: 1, CorrelationID: "start-1"}
	entry := func(id identity.UserID, version uint64) ImpersonationApproverAdmission {
		return ImpersonationApproverAdmission{ApprovalCommandID: newID(),
			User: identity.User{ID: id, TenantID: b.TenantID, Status: identity.StatusActive, Version: version},
			Authorization: UserAuthorizationAdmission{Scope: authority.AuthorityScope{
				TenantID: "tenant", SubjectID: authorization.SubjectID(id), PolicyNamespace: "administration",
			}, Version: version + 1}}
	}
	reviewers := []ImpersonationApproverAdmission{entry("first-reviewer", 3), entry("second-reviewer", 7)}
	field, err := ImpersonationApproverSetField(b, reviewers)
	if err != nil || field.Name != "impersonation.approver-set" || field.Value.Kind != identity.FeatureBytes || len(field.Value.Bytes) != 32 {
		t.Fatal("cannot bind the selected reviewer set", err)
	}
	command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: []identity.FeatureField{field}})
	if err != nil {
		t.Fatal(err)
	}
	l := LifecyclePlan{EventType: "impersonation.started.v1", BeforeVersion: 3, AfterVersion: 4}
	if !impersonationApproverSetMatches(b, registration, l, command, reviewers) {
		t.Fatal("the original complete reviewer set did not match")
	}
	swapped := []ImpersonationApproverAdmission{reviewers[1], reviewers[0]}
	stale := slices.Clone(reviewers)
	stale[0].Authorization.Version--
	wrongCommand := slices.Clone(reviewers)
	wrongCommand[1].ApprovalCommandID = newID()
	for name, set := range map[string][]ImpersonationApproverAdmission{
		"subset": reviewers[:1], "order": swapped, "stale epoch": stale, "other decision": wrongCommand,
	} {
		t.Run(name, func(t *testing.T) {
			if impersonationApproverSetMatches(b, registration, l, command, set) {
				t.Fatal("a different approval set matched the original command")
			}
		})
	}
	if impersonationApproverSetMatches(b, registration, LifecyclePlan{EventType: l.EventType, BeforeVersion: 2, AfterVersion: 3}, command, reviewers) {
		t.Fatal("a legacy one-approval lifecycle admitted two reviewers")
	}
	for name, invalid := range map[string][]ImpersonationApproverAdmission{
		"one reviewer": reviewers[:1], "duplicate reviewer": {reviewers[0], reviewers[0]},
		"requester": {entry("requester", 1), reviewers[1]}, "target": {entry("target", 1), reviewers[1]},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ImpersonationApproverSetField(b, invalid); err == nil {
				t.Fatal("invalid set received a command binding")
			}
		})
	}
}
