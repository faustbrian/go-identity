package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestVerificationSigninMappingSeparatesItsNativeCommand(t *testing.T) {
	for _, csrf := range []bool{false, true} {
		feature, original := magicLinkSigninMappingFixture(t, csrf)
		spec, _ := original.Bindings()
		feature.Binding.AnonymousFlowID = ""
		parent, _ := identity.NewCommandID()
		feature.Binding.UserID, feature.Binding.RecordID = spec.UserID, string(parent)
		feature.Binding.OperationID, feature.Binding.SchemaID = "identity.email.verification-signin", "email-verification-signin"
		feature.Operation = identity.FeatureOperation{Owner: "identity/email", OperationID: feature.Binding.OperationID, SchemaID: feature.Binding.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
		command, err := identity.NewFeatureCommand(feature)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := EmailVerificationSigninSession(command)
		if err != nil {
			t.Fatal("exact verification signin projection denied", err)
		}
		want, _, _ := encodeRecord(original)
		got, _, _ := encodeRecord(restored)
		if !bytes.Equal(want, got) {
			t.Fatal("grant, remember, authority or synchronizer changed")
		}
		if _, err := MagicLinkSigninSession(command); err == nil {
			t.Fatal("verification became ordinary magic-link consumption")
		}
		for _, change := range []func(*identity.FeatureCommandSpec){
			func(f *identity.FeatureCommandSpec) { f.Binding.UserID = "foreign-user" },
			func(f *identity.FeatureCommandSpec) { f.Binding.RecordID = "other-session" },
			func(f *identity.FeatureCommandSpec) { f.Fields = f.Fields[:len(f.Fields)-1] },
		} {
			bad := feature
			bad.Fields = append([]identity.FeatureField{}, feature.Fields...)
			change(&bad)
			wrong, err := identity.NewFeatureCommand(bad)
			if err == nil {
				if _, err := EmailVerificationSigninSession(wrong); err == nil {
					t.Fatal("substituted verification signin scope admitted")
				}
			}
		}
	}
}

func FuzzVerificationSigninMapping(f *testing.F) {
	f.Add(uint8(0), "invalid")
	f.Add(uint8(23), "2026-10-11T00:00:00Z")
	spec, original := magicLinkSigninMappingFixture(f, true)
	s, _ := original.Bindings()
	parent, _ := identity.NewCommandID()
	spec.Binding.UserID, spec.Binding.AnonymousFlowID, spec.Binding.RecordID = s.UserID, "", string(parent)
	spec.Binding.OperationID, spec.Binding.SchemaID = "identity.email.verification-signin", "email-verification-signin"
	spec.Operation = verificationSigninOperation()
	f.Fuzz(func(t *testing.T, index uint8, input string) {
		if len(input) > 8192 {
			return
		}
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
		i := int(index) % len(changed.Fields)
		changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: input}
		command, err := identity.NewFeatureCommand(changed)
		if err != nil {
			return
		}
		record, err := EmailVerificationSigninSession(command)
		if err != nil {
			return
		}
		fields, err := MagicLinkSigninSessionFields(record)
		if err != nil {
			t.Fatal("accepted verification session cannot be remapped", err)
		}
		changed.Fields = fields
		canonical, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		again, err := EmailVerificationSigninSession(canonical)
		a, _, _ := encodeRecord(record)
		b, _, _ := encodeRecord(again)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("accepted verification projection is not canonically stable", err)
		}
	})
}
