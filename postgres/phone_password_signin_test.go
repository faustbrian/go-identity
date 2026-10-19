package postgres

import (
	"bytes"
	"encoding/base64"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func phonePasswordCodecSpec() identity.FeatureCommandSpec {
	spec := passwordSigninCodecSpec(true)
	spec.Operation.Owner = "identity/phone"
	spec.Operation.OperationID, spec.Operation.SchemaID = "identity.phone.password-signin", "phone-password-signin"
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	return spec
}

func TestPhonePasswordSigninNativeCustodyCannotBeOmitted(t *testing.T) {
	spec := phonePasswordCodecSpec()
	wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{32}, 32))
	command, _ := passwordSigninCodecCommand(t, spec, []byte(" synthetic phone comparison "), wire)
	claim, err := prepareClaim(command, [32]byte{1})
	if err != nil || claim.feature == nil || *claim.feature != spec.Operation || claim.purpose != "identity.phone.password-signin" {
		t.Fatal("native fingerprint lost exact phone password profile", err)
	}
	plain := featureCodecCommand(t, spec)
	if _, err := prepareClaim(plain, [32]byte{1}); err == nil {
		t.Fatal("phone password signin admitted without paired credential custody")
	}
	changed, _ := passwordSigninCodecCommand(t, spec, []byte(" different phone comparison "), wire)
	other, err := prepareClaim(changed, [32]byte{1})
	if err != nil || bytes.Equal(other.canonical, claim.canonical) || !bytes.Equal(other.safeFields, claim.safeFields) {
		t.Fatal("phone password change did not alter secret-bound intent only")
	}
}

func TestPhonePasswordSigninUsesOnlyExactExistingNativeOwner(t *testing.T) {
	spec := phonePasswordCodecSpec()
	descriptor := ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
	for _, alter := range []func(*ContributorDescriptor, *identity.FeatureOperation){
		nil,
		func(d *ContributorDescriptor, _ *identity.FeatureOperation) {
			d.Owner, d.ContractID = "identity/phone/postgres", "identity.phone"
		},
		func(d *ContributorDescriptor, _ *identity.FeatureOperation) { d.ContractID = "other" },
		func(d *ContributorDescriptor, _ *identity.FeatureOperation) { d.Version = 2 },
		func(_ *ContributorDescriptor, op *identity.FeatureOperation) { op.SchemaID = "password-signin" },
		func(_ *ContributorDescriptor, op *identity.FeatureOperation) {
			op.OperationID = "identity.phone.signin"
		},
		func(_ *ContributorDescriptor, op *identity.FeatureOperation) { op.SchemaVersion = 2 },
	} {
		d, op := descriptor, spec.Operation
		if alter != nil {
			alter(&d, &op)
		}
		owner := &featureRegistryContributor{descriptor: d, operations: []identity.FeatureOperation{op}}
		registry, err := NewContributorRegistry([]Contributor{owner})
		if alter == nil {
			if err != nil || registry == nil || len(registry.FeatureOperations()) != 1 || registry.FeatureOperations()[0].Operation != spec.Operation {
				t.Fatal("exact native password owner cannot own phone signin", err)
			}
		} else if err == nil || registry != nil {
			t.Fatal("foreign native owner or unselected phone profile admitted")
		}
	}
}

func TestPhonePasswordSigninHashUpgradeRetainsExactPredecessors(t *testing.T) {
	want := passwordUpgradeIntentFixture()
	spec := passwordUpgradeSpecFixture(t, want)
	spec.Operation.Owner = "identity/phone"
	spec.Operation.OperationID, spec.Operation.SchemaID = "identity.phone.password-signin", "phone-password-signin"
	spec.Binding.OperationID, spec.Binding.SchemaID = spec.Operation.OperationID, spec.Operation.SchemaID
	got, err := decodePasswordHashUpgrade(spec)
	if err != nil || got != want {
		t.Fatal("phone password rehash lost original credential fences", err)
	}
}
