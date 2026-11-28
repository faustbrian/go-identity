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
	for _, action := range []string{"request", "approve"} {
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
				ActorKind: authorization.SubjectUser, RecordID: string(id),
				OperationID: registration.Operation.OperationID, SchemaID: registration.Operation.SchemaID,
				SchemaVersion: 1, PolicyID: "administrator-policy", PolicyVersion: 1, CorrelationID: string(id),
			}
			if !impersonationActorTOTPBindingMatches(binding, registration, "administrator") {
				t.Fatal("exact approval operation did not bind the administrator's factor")
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
				{name: "activation", actor: "administrator", alter: func(b *identity.CommandBinding, f *kernel.FeatureRegistration) {
					b.OperationID = "identity.impersonation.start"
					f.Operation.OperationID = b.OperationID
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
		})
	}
}
