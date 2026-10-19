package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestPhoneOTPSigninUsesOnlyExactNativeOTPOwner(t *testing.T) {
	for _, subject := range []identity.FeatureSubjectRequirement{identity.FeatureSubjectUser, identity.FeatureSubjectAnonymousFlow} {
		descriptor := ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1}
		operation := identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.signin", SchemaID: "identity.phone.signin.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: subject}
		for _, alter := range []func(*ContributorDescriptor, *identity.FeatureOperation){
			nil,
			func(d *ContributorDescriptor, _ *identity.FeatureOperation) {
				d.Owner, d.ContractID = "identity/phone/postgres", "identity.phone"
			},
			func(d *ContributorDescriptor, _ *identity.FeatureOperation) {
				d.Owner, d.ContractID = "identity/password/postgres", "identity.password"
			},
			func(d *ContributorDescriptor, _ *identity.FeatureOperation) { d.ContractID = "alternate" },
			func(d *ContributorDescriptor, _ *identity.FeatureOperation) { d.Version++ },
			func(_ *ContributorDescriptor, op *identity.FeatureOperation) { op.SchemaID = "identity-otp-signin" },
			func(_ *ContributorDescriptor, op *identity.FeatureOperation) { op.SchemaVersion++ },
			func(_ *ContributorDescriptor, op *identity.FeatureOperation) {
				op.RecordRequirement = identity.FeatureRecordRequired
			},
		} {
			d, op := descriptor, operation
			if alter != nil {
				alter(&d, &op)
			}
			registry, err := NewContributorRegistry([]Contributor{&featureRegistryContributor{descriptor: d, operations: []identity.FeatureOperation{op}}})
			if alter == nil {
				if err != nil || registry == nil || len(registry.FeatureOperations()) != 1 || registry.FeatureOperations()[0] != (FeatureRegistration{Contributor: descriptor, Operation: operation}) {
					t.Fatal("exact phone OTP workflow cannot reuse its native participant", err)
				}
			} else if err == nil || registry != nil {
				t.Fatal("foreign phone OTP owner or unsupported profile admitted")
			}
		}
	}
}
