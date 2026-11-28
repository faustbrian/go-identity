package mfapostgres

import (
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestImpersonationActorTOTPBindingRequiresExactOwnerAndDistinctActor(t *testing.T) {
	id, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	grantID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"request", "approve", "start"} {
		t.Run(action, func(t *testing.T) {
			registration := kernel.FeatureRegistration{
				Operation: identity.FeatureOperation{
					Owner: "identity/impersonation", OperationID: "identity.impersonation." + action,
					SchemaID: "impersonation-" + action, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
				},
				Contributor: kernel.ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1},
			}
			binding := identity.CommandBinding{
				CommandID: id, TenantID: "tenant", UserID: "target", ActorID: "administrator",
				ActorKind: authorization.SubjectUser, RecordID: string(grantID),
				OperationID: registration.Operation.OperationID, SchemaID: registration.Operation.SchemaID,
				SchemaVersion: 1, PolicyID: "administrator-policy", PolicyVersion: 1, CorrelationID: string(id),
			}
			if !impersonationActorTOTPBindingMatches(binding, registration, "administrator") {
				t.Fatal("exact impersonation operation did not bind the administrator's factor")
			}
			for _, tc := range []struct {
				name  string
				actor identity.UserID
				alter func(*identity.CommandBinding, *kernel.FeatureRegistration)
			}{
				{name: "target factor", actor: "target"},
				{name: "foreign actor", actor: "foreign"},
				{name: "same subject", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.UserID = "administrator" }},
				{name: "service actor", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) {
					b.ActorKind = authorization.SubjectServiceAccount
				}},
				{name: "other contributor", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
					f.Contributor.Owner = "identity/session/postgres"
				}},
				{name: "unrecognized schema", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
					b.SchemaVersion, f.Operation.SchemaVersion = 2, 2
				}},
				{name: "stop", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
					b.OperationID = "identity.impersonation.stop"
					f.Operation.OperationID = b.OperationID
				}},
				{name: "other schema", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
					b.SchemaID, f.Operation.SchemaID = "impersonation-stop", "impersonation-stop"
				}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					b, f := binding, registration
					if tc.alter != nil {
						tc.alter(&b, &f)
					}
					if impersonationActorTOTPBindingMatches(b, f, tc.actor) {
						t.Fatal("unselected operation or actor could use the impersonation factor gate")
					}
				})
			}
			if action == "start" {
				binding.RecordID = string(id)
				if impersonationActorTOTPBindingMatches(binding, registration, "administrator") {
					t.Fatal("activation reused its command ID as antecedent grant")
				}
			}
		})
	}
}

func TestImpersonationActorTOTPBindingAdmitsOnlyExactRevoke(t *testing.T) {
	commandID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	grantID, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	registration := kernel.FeatureRegistration{
		Operation: identity.FeatureOperation{
			Owner: "identity/impersonation", OperationID: "identity.impersonation.revoke",
			SchemaID: "impersonation-revoke", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired,
		},
		Contributor: kernel.ContributorDescriptor{Owner: "identity/impersonation/postgres", ContractID: "identity.impersonation", Version: 1},
	}
	binding := identity.CommandBinding{
		CommandID: commandID, TenantID: "tenant", UserID: "target", ActorID: "administrator",
		ActorKind: authorization.SubjectUser, RecordID: string(grantID),
		OperationID: registration.Operation.OperationID, SchemaID: registration.Operation.SchemaID,
		SchemaVersion: 1, PolicyID: "administrator-policy", PolicyVersion: 1, CorrelationID: string(commandID),
	}
	for _, tc := range []struct {
		name  string
		actor identity.UserID
		alter func(*identity.CommandBinding, *kernel.FeatureRegistration)
		want  bool
	}{
		{name: "exact revoke", actor: "administrator", want: true},
		{name: "empty actor"},
		{name: "target factor", actor: "target"},
		{name: "foreign actor", actor: "foreign"},
		{name: "same subject", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.UserID = "administrator" }},
		{name: "missing target", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.UserID = "" }},
		{name: "service actor", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) {
			b.ActorKind = authorization.SubjectServiceAccount
		}},
		{name: "API key actor", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) {
			b.ActorKind = authorization.SubjectAPIKey
		}},
		{name: "other owner", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Operation.Owner = "identity/session"
		}},
		{name: "other contributor", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Contributor.Owner = "identity/session/postgres"
		}},
		{name: "other contract", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Contributor.ContractID = "identity.session"
		}},
		{name: "other contributor version", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) { f.Contributor.Version = 2 }},
		{name: "other schema", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
			b.SchemaID, f.Operation.SchemaID = "impersonation-start", "impersonation-start"
		}},
		{name: "other schema version", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
			b.SchemaVersion, f.Operation.SchemaVersion = 2, 2
		}},
		{name: "other operation", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
			b.OperationID, f.Operation.OperationID = "identity.impersonation.stop", "identity.impersonation.stop"
		}},
		{name: "omitted record registration", actor: "administrator", alter: func(_ *identity.CommandBinding, f *kernel.FeatureRegistration) {
			f.Operation.RecordRequirement = identity.FeatureRecordOmitted
		}},
		{name: "missing grant", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.RecordID = "" }},
		{name: "noncanonical grant", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.RecordID = "grant" }},
		{name: "command substituted for grant", actor: "administrator", alter: func(b *identity.CommandBinding, _ *kernel.FeatureRegistration) { b.RecordID = string(commandID) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, f := binding, registration
			if tc.alter != nil {
				tc.alter(&b, &f)
			}
			if got := impersonationActorTOTPBindingMatches(b, f, tc.actor); got != tc.want {
				t.Fatalf("revoke actor factor admission = %t, want %t", got, tc.want)
			}
		})
	}
}
