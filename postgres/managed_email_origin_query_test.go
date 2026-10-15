package postgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func TestManagedEmailPreparationRejectsZeroComposition(t *testing.T) {
	for _, c := range []*Coordinator{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			binding, wire, generation, err := c.QueryManagedEmailPreparation(ctx, identity.RecoveryQuery{}, authorization.DecisionContext{}, FeatureRegistration{}, nil)
			if err == nil || binding != (identity.CommandBinding{}) || wire != nil || generation != 0 {
				t.Fatal("invalid management composition disclosed intent")
			}
		}
	}
}

func TestManagedEmailOriginHasClosedConfirmationMapping(t *testing.T) {
	for _, request := range []string{"identity.email.verification-send", "identity.email.change-request"} {
		confirm := "identity.email.verification-confirm"
		if request == "identity.email.change-request" {
			confirm = "identity.email.change-confirm"
		}
		feature := FeatureRegistration{Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}, Operation: identity.FeatureOperation{Owner: "identity/email", OperationID: request, SchemaID: request + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}}
		if !managedEmailOriginOperation(feature, confirm) {
			t.Fatal("original request lost its confirmation action")
		}
		for _, mutate := range []func(*FeatureRegistration){
			func(f *FeatureRegistration) { f.Contributor.Owner = "identity/password/postgres" },
			func(f *FeatureRegistration) { f.Contributor.ContractID = "identity.password" },
			func(f *FeatureRegistration) { f.Contributor.Version++ },
			func(f *FeatureRegistration) { f.Operation.Owner = "identity/password" },
			func(f *FeatureRegistration) { f.Operation.OperationID = "identity.password.signup" },
			func(f *FeatureRegistration) { f.Operation.SchemaID = request + ".other" },
			func(f *FeatureRegistration) { f.Operation.SchemaVersion++ },
			func(f *FeatureRegistration) { f.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow },
			func(f *FeatureRegistration) { f.Operation.RecordRequirement = 0 },
		} {
			other := feature
			mutate(&other)
			if managedEmailOriginOperation(other, confirm) {
				t.Fatal("foreign operation acquired management-origin disclosure")
			}
		}
		for _, other := range []string{"", request, "identity.password.signup", "identity.email.address-remove"} {
			if managedEmailOriginOperation(feature, other) {
				t.Fatal("unrelated action acquired original output")
			}
		}
	}
}
