package postgres

import (
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
)

func TestImpersonationActivationAndApprovalParticipantFences(t *testing.T) {
	requester, approver := identity.UserID("requester"), identity.UserID("approver")
	for _, tc := range []struct {
		action, schema string
		actor          identity.UserID
	}{
		{"identity.impersonation.approve", "impersonation-approve", approver},
		{"identity.impersonation.start", "impersonation-start", requester},
	} {
		t.Run(tc.schema, func(t *testing.T) {
			id, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			grant, err := identity.NewCommandID()
			if err != nil {
				t.Fatal(err)
			}
			op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: tc.action, SchemaID: tc.schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			reg := FeatureRegistration{Operation: op, Contributor: ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}}
			binding := identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "target", ActorID: identity.ActorID(tc.actor), ActorKind: authorization.SubjectUser, OperationID: tc.action, SchemaID: tc.schema, SchemaVersion: 1, RecordID: string(grant), CorrelationID: string(id), PolicyID: "admin", PolicyVersion: 1}
			requesterUser := identity.User{ID: requester, TenantID: "tenant", Status: identity.StatusActive, Version: 3}
			approverUser := identity.User{ID: approver, TenantID: "tenant", Status: identity.StatusActive, Version: 7}
			reqPolicy := UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: "tenant", SubjectID: "requester", PolicyNamespace: "users"}, Version: 4}
			appPolicy := UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: "tenant", SubjectID: "approver", PolicyNamespace: "users"}, Version: 8}
			command, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{
				{Name: "impersonation.requester-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(requester)}},
				{Name: "impersonation.requester-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: requesterUser.Version}},
				{Name: "impersonation.requester-namespace", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "users"}},
				{Name: "impersonation.requester-authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: reqPolicy.Version}},
				{Name: "impersonation.approver-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(approver)}},
				{Name: "impersonation.approver-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: approverUser.Version}},
				{Name: "impersonation.approver-namespace", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "users"}},
				{Name: "impersonation.approver-authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: appPolicy.Version}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if !impersonationApproverMatches(binding, reg, command, approverUser, appPolicy) ||
				!impersonationRequesterMatches(binding, reg, command, requesterUser, reqPolicy) {
				t.Fatal("both frozen participants must retain their own authority")
			}
			if impersonationApproverMatches(binding, reg, command, requesterUser, reqPolicy) ||
				impersonationRequesterMatches(binding, reg, command, approverUser, appPolicy) {
				t.Fatal("participant roles substituted for one another")
			}
			appPolicy.Version++
			if impersonationApproverMatches(binding, reg, command, approverUser, appPolicy) {
				t.Fatal("current policy substituted the retained approval epoch")
			}
		})
	}
}

func TestImpersonationRequesterBindsFrozenApprovalSubject(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	op := identity.FeatureOperation{Owner: "identity/impersonation", OperationID: "identity.impersonation.approve", SchemaID: "impersonation-approve", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	registration := FeatureRegistration{Operation: op, Contributor: ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1}}
	binding := identity.CommandBinding{CommandID: id, TenantID: "tenant", UserID: "target", ActorID: "approver", ActorKind: authorization.SubjectUser, OperationID: op.OperationID, SchemaID: op.SchemaID, SchemaVersion: 1, RecordID: string(id), CorrelationID: string(id), PolicyID: "admin", PolicyVersion: 1}
	requester := identity.User{ID: "requester", TenantID: "tenant", Status: identity.StatusActive, Version: 3}
	expected := UserAuthorizationAdmission{Scope: authority.AuthorityScope{TenantID: "tenant", SubjectID: "requester", PolicyNamespace: "users"}, Version: 4}
	command := func(requesterID string, version uint64) identity.Command {
		cmd, err := identity.NewFeatureCommand(identity.FeatureCommandSpec{Binding: binding, Operation: op, Fields: []identity.FeatureField{
			{Name: "impersonation.requester-id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: requesterID}},
			{Name: "impersonation.requester-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: version}},
			{Name: "impersonation.requester-namespace", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "users"}},
			{Name: "impersonation.requester-authority", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 4}},
		}})
		if err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	if !impersonationRequesterMatches(binding, registration, command("requester", 3), requester, expected) {
		t.Fatal("original requester cannot be checked during the exact approval")
	}
	for _, candidate := range []identity.Command{command("target", 3), command("approver", 3), command("requester", 2), {}} {
		if impersonationRequesterMatches(binding, registration, candidate, requester, expected) {
			t.Fatal("requester fence accepted a different frozen authority")
		}
	}
	foreign := expected
	foreign.Scope.SubjectID = "approver"
	if impersonationRequesterMatches(binding, registration, command("requester", 3), requester, foreign) {
		t.Fatal("approver's epoch satisfied the original requester fence")
	}
}
