package passwordpostgres

import (
	"errors"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func phoneResetMaterialOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.password-reset-complete", SchemaID: "identity.phone.password-reset-complete.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// Structural material mapping cannot establish recovery eligibility or signed
// grant scope. Native admission and the real capability/OTP/MFA/risk owners must
// establish those independently before the canonical writer receives Work.
func TestPhoneResetMaterialKeepsCanonicalWriterAndOriginalJointCustody(t *testing.T) {
	spec, previous, encoded, policy := replacementFixture(t)
	spec.Operation = phoneResetMaterialOperation()
	spec.Binding.OperationID, spec.Binding.SchemaID, spec.Binding.SchemaVersion = spec.Operation.OperationID, spec.Operation.SchemaID, spec.Operation.SchemaVersion
	intent := kernel.CredentialResetIntent{Replacement: previous, ExpectedEnabled: true}
	fields, err := kernel.CredentialResetFields(intent)
	if err != nil {
		t.Fatal(err)
	}
	spec.Fields = append(fields, identity.FeatureField{Name: "phone.original-profile", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: "synthetic-original-scope"}})
	proof := resetMaterialProof(t)
	sms, _ := auth.NewOneTimeCode("123456")
	totp, _ := auth.NewOneTimeCode("654321")
	command, err := identity.NewFeaturePhonePasswordResetCommand(spec, encoded, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	got, hash, err := passwordResetMaterial(command, policy)
	if err != nil || got != intent || hash.String() != encoded {
		t.Fatal("joint phone recovery cannot reach canonical reset material mapping", err)
	}
	retained, ok := command.PhonePasswordResetFeature()
	if !ok || len(retained.Fields) != len(spec.Fields) {
		t.Fatal("mapping discarded native recovery scope")
	}
	_, originalProof, originalSMS, originalTOTP, ok := command.PhonePasswordResetCustody()
	if !ok || originalProof.ValidateBounds(32, 4096) != nil {
		t.Fatal("mapping consumed joint custody")
	}
	for _, pair := range [][2]auth.OneTimeCode{{sms, originalSMS}, {totp, originalTOTP}} {
		want, _ := pair[0].CommandDigest([32]byte{1}, "material-test")
		got, err := pair[1].CommandDigest([32]byte{1}, "material-test")
		if err != nil || got != want {
			t.Fatal("mapping substituted a code")
		}
	}
	if _, ok := command.PasswordResetFeature(); ok {
		t.Fatal("phone command converted into legacy email reset")
	}
	for _, mutate := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaID = "alias"; s.Binding.SchemaID = "alias" },
		func(s *identity.FeatureCommandSpec) { s.Fields[0].Value.Text = "foreign" },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "credential.unknown", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: 1}})
		},
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "reset.unknown", Value: identity.FeatureValue{Kind: identity.FeatureBool, Bool: true}})
		},
	} {
		bad := spec
		bad.Fields = append([]identity.FeatureField(nil), spec.Fields...)
		mutate(&bad)
		c, err := identity.NewFeaturePhonePasswordResetCommand(bad, encoded, proof, sms, totp)
		if err != nil {
			continue
		}
		if i, h, err := passwordResetMaterial(c, policy); !errors.Is(err, password.ErrPasswordWork) || i != (kernel.CredentialResetIntent{}) || h.String() != "" {
			t.Fatal("foreign or unknown password-owned material metadata accepted")
		}
	}
	generic, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := passwordResetMaterial(generic, policy); !errors.Is(err, password.ErrPasswordWork) {
		t.Fatal("unsealed metadata acquired phone-reset material")
	}
}

func TestPhoneResetMaterialEffectScopeRetainsResetNotChange(t *testing.T) {
	op := phoneResetMaterialOperation()
	life := kernel.LifecyclePlan{EventType: "password.reset.v1", BeforeVersion: 3, AfterVersion: 4}
	if !replacementEffectScope(op, life) {
		t.Fatal("canonical password writer cannot retain phone reset effects")
	}
	for _, mutate := range []func(*identity.FeatureOperation, *kernel.LifecyclePlan){
		func(op *identity.FeatureOperation, _ *kernel.LifecyclePlan) { op.Owner = "identity/password" },
		func(op *identity.FeatureOperation, _ *kernel.LifecyclePlan) { op.SchemaVersion++ },
		func(_ *identity.FeatureOperation, l *kernel.LifecyclePlan) { l.EventType = "password.changed.v1" },
		func(_ *identity.FeatureOperation, l *kernel.LifecyclePlan) { l.AfterVersion++ },
	} {
		bad, changed := op, life
		mutate(&bad, &changed)
		if replacementEffectScope(bad, changed) {
			t.Fatal("phone reset acquired an unrelated replacement effect")
		}
	}
}
