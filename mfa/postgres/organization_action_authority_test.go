package mfapostgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestOrganizationLifecycleFactorsRequireOneExactSelfGeneration(t *testing.T) {
	for _, action := range []string{"identity.organization.archive", "identity.organization.restore"} {
		t.Run(action, func(t *testing.T) {
			s, reg := actionFactorFixture(t, false)
			s.Operation = identity.FeatureOperation{Owner: "organization", OperationID: action, SchemaID: "organization-lifecycle", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
			s.Binding.OperationID = action
			s.Binding.SchemaID = s.Operation.SchemaID
			reg = kernel.FeatureRegistration{Contributor: kernel.ContributorDescriptor{Owner: "organization/postgres", ContractID: "organization.membership", Version: 1}, Operation: s.Operation}
			subjects, err := actionPrimaryFactorSubjects(s, reg, 7, 7)
			if err != nil || len(subjects) != 1 || subjects[0].user != s.Binding.UserID || subjects[0].version != 7 {
				t.Fatal("self-only lifecycle factor custody denied", err)
			}
			for _, mode := range []string{"foreign-target", "unequal-generation", "wrong-schema", "wrong-owner", "wrong-action"} {
				request, registration := s, reg
				target := uint64(7)
				switch mode {
				case "foreign-target":
					request.Binding.UserID = "foreign"
				case "unequal-generation":
					target++
				case "wrong-schema":
					request.Operation.SchemaID = "organization-membership"
					registration.Operation = request.Operation
				case "wrong-owner":
					registration.Contributor.Owner = "foreign"
				case "wrong-action":
					request.Operation.OperationID = "identity.organization.delete"
					registration.Operation = request.Operation
				}
				if _, err := actionPrimaryFactorSubjects(request, registration, 7, target); err == nil {
					t.Fatal("foreign lifecycle factor scope accepted", mode)
				}
			}
		})
	}
}
