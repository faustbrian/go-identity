package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestPhoneChangeRegistryRejectsUnsupportedDescriptors(t *testing.T) {
	for name, alter := range map[string]func(*identity.FeatureOperation, *ContributorDescriptor){
		"schema": func(o *identity.FeatureOperation, _ *ContributorDescriptor) {
			o.SchemaID = "identity.phone.update.other"
		},
		"version": func(o *identity.FeatureOperation, _ *ContributorDescriptor) { o.SchemaVersion++ },
		"owner": func(o *identity.FeatureOperation, d *ContributorDescriptor) {
			o.Owner, d.Owner = "identity/other", "identity/other/postgres"
		},
		"record-policy": func(o *identity.FeatureOperation, _ *ContributorDescriptor) {
			o.RecordRequirement = identity.FeatureRecordOmitted
		},
		"contract": func(_ *identity.FeatureOperation, d *ContributorDescriptor) { d.ContractID = "identity.phone.generic" },
	} {
		t.Run(name, func(t *testing.T) {
			op, descriptor := phoneChangeOperation(), (ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1})
			alter(&op, &descriptor)
			if op.Validate() != nil || !validContributorDescriptor(descriptor) {
				t.Fatal("malformed fixture cannot exercise reserved operation ownership")
			}
			if _, err := NewContributorRegistry([]Contributor{&featureRegistryContributor{descriptor: descriptor, operations: []identity.FeatureOperation{op}}}); err == nil {
				t.Fatal("unsupported phone update entered the generic registry")
			}
		})
	}
}
