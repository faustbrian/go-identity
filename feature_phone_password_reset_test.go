package identity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password/v2"
)

func phonePasswordResetSpec() identity.FeatureCommandSpec {
	s := passwordResetSpec()
	s.Operation.Owner = "identity/phone"
	s.Operation.OperationID = "identity.phone.password-reset-complete"
	s.Operation.SchemaID = "identity.phone.password-reset-complete.native-v1"
	s.Binding.OperationID, s.Binding.SchemaID = s.Operation.OperationID, s.Operation.SchemaID
	return s
}

func TestPhonePasswordResetCommandRetainsJointCustodyWithoutLegacyDowngrade(t *testing.T) {
	proof, wire := passwordResetProof(t, 0)
	secret, err := primitive.NewSecret([]byte("original phone reset password"))
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Destroy()
	sms, _ := auth.NewOneTimeCode("123456")
	totp, _ := auth.NewOneTimeCode("654321")
	spec := phonePasswordResetSpec()
	input, err := identity.NewFeaturePhonePasswordResetInputCommand(spec, secret, proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	generated, err := identity.NewFeaturePhonePasswordResetCommand(spec, "$synthetic$replacement", proof, sms, totp)
	if err != nil {
		t.Fatal(err)
	}
	spec.Fields[2].Value.Bytes[0] = 99
	for _, c := range []identity.Command{input, generated} {
		if _, ok := c.Feature(); ok {
			t.Fatal("ordinary feature omitted recovery factors")
		}
		if _, ok := c.PasswordResetFeature(); ok {
			t.Fatal("email reset omitted recovery factors")
		}
		if _, ok := c.PasswordResetInputFeature(); ok {
			t.Fatal("email preparation omitted recovery factors")
		}
		if _, ok := c.OneTimeCode(); ok {
			t.Fatal("single-code path omitted the independent factor")
		}
		if _, _, ok := c.PasswordResetCustody(); ok {
			t.Fatal("email reset borrowed partial custody")
		}
		if _, _, ok := c.PasswordResetInputCustody(); ok {
			t.Fatal("email preparation borrowed partial custody")
		}
		for _, formatted := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
			for _, sensitive := range []string{wire, "123456", "654321", "original phone reset", "$synthetic$replacement"} {
				if strings.Contains(formatted, sensitive) {
					t.Fatal("joint recovery custody leaked")
				}
			}
		}
		if _, err := json.Marshal(c); err == nil {
			t.Fatal("joint recovery command serialized")
		}
	}
	metadata, ok := input.PhonePasswordResetInputFeature()
	if !ok || metadata.Binding != phonePasswordResetSpec().Binding {
		t.Fatal("original phone reset scope lost")
	}
	for _, field := range metadata.Fields {
		if field.Value.Kind == identity.FeatureBytes && field.Value.Bytes[0] != 1 {
			t.Fatal("metadata aliases original")
		}
	}
	metadata.Fields[0].Name = "changed"
	again, _ := input.PhonePasswordResetInputFeature()
	if again.Fields[0].Name == "changed" {
		t.Fatal("metadata aliases returned projection")
	}
	password, original, gotSMS, gotTOTP, ok := input.PhonePasswordResetInputCustody()
	if !ok {
		t.Fatal("joint original custody missing")
	}
	if err := password.Use(func(raw []byte) error {
		if !bytes.Equal(raw, []byte("original phone reset password")) {
			t.Fatal("password changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]auth.OneTimeCode{{sms, gotSMS}, {totp, gotTOTP}} {
		want, _ := pair[0].CommandDigest([32]byte{1}, "test")
		got, err := pair[1].CommandDigest([32]byte{1}, "test")
		if err != nil || got != want {
			t.Fatal("factor code lost or swapped")
		}
	}
	hash, generatedProof, _, _, ok := generated.PhonePasswordResetCustody()
	if !ok || hash != "$synthetic$replacement" {
		t.Fatal("generated joint custody lost")
	}
	if _, ok := input.PhonePasswordResetFeature(); ok {
		t.Fatal("input masqueraded as generated verifier")
	}
	if _, ok := generated.PhonePasswordResetInputFeature(); ok {
		t.Fatal("generated verifier masqueraded as original password")
	}
	if err := original.Transfer(context.Background(), func(_ context.Context, raw []byte) error {
		if string(raw) != wire {
			t.Fatal("proof changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if generatedProof.ValidateBounds(32, 4096) == nil || proof.ValidateBounds(32, 4096) == nil {
		t.Fatal("joint command cloned one-use proof custody")
	}
	secret.Destroy()
	if password.Use(func([]byte) error { t.Fatal("password resurrected"); return nil }) == nil {
		t.Fatal("destroyed password survived")
	}
}

func TestPhonePasswordResetCommandRejectsMissingInputsAndForeignScope(t *testing.T) {
	proof, _ := passwordResetProof(t, 0)
	secret, _ := primitive.NewSecret([]byte("synthetic"))
	defer secret.Destroy()
	code, _ := auth.NewOneTimeCode("123456")
	for _, pair := range [][2]auth.OneTimeCode{{{}, code}, {code, {}}, {{}, {}}} {
		if c, err := identity.NewFeaturePhonePasswordResetInputCommand(phonePasswordResetSpec(), secret, proof, pair[0], pair[1]); err == nil || c != (identity.Command{}) {
			t.Fatal("missing independent code accepted")
		}
		if c, err := identity.NewFeaturePhonePasswordResetCommand(phonePasswordResetSpec(), "synthetic", proof, pair[0], pair[1]); err == nil || c != (identity.Command{}) {
			t.Fatal("generated command omitted independent code")
		}
	}
	if c, err := identity.NewFeaturePhonePasswordResetInputCommand(phonePasswordResetSpec(), primitive.Secret{}, proof, code, code); err == nil || c != (identity.Command{}) {
		t.Fatal("zero password admitted")
	}
	for _, hash := range []string{"", "line\nbreak", strings.Repeat("x", 16385)} {
		if c, err := identity.NewFeaturePhonePasswordResetCommand(phonePasswordResetSpec(), hash, proof, code, code); err == nil || c != (identity.Command{}) {
			t.Fatal("invalid verifier transport admitted")
		}
	}
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { *s = passwordResetSpec() },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/password" },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.OperationID = "identity.phone.password-reset-request"
		},
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaID = "public-request" },
		func(s *identity.FeatureCommandSpec) { s.Operation.SchemaVersion++ },
		func(s *identity.FeatureCommandSpec) { s.Operation.RecordRequirement = identity.FeatureRecordOmitted },
		func(s *identity.FeatureCommandSpec) {
			s.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
		},
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "" },
		func(s *identity.FeatureCommandSpec) { s.Fields = append(s.Fields, s.Fields[0]) },
	} {
		s := phonePasswordResetSpec()
		change(&s)
		if c, err := identity.NewFeaturePhonePasswordResetInputCommand(s, secret, proof, code, code); err == nil || c != (identity.Command{}) {
			t.Fatal("foreign/incomplete original profile admitted")
		}
		if c, err := identity.NewFeaturePhonePasswordResetCommand(s, "synthetic", proof, code, code); err == nil || c != (identity.Command{}) {
			t.Fatal("foreign/incomplete generated profile admitted")
		}
	}
	if c, err := identity.NewFeaturePhonePasswordResetInputCommand(phonePasswordResetSpec(), secret, capability.Proof{}, code, code); err == nil || c != (identity.Command{}) {
		t.Fatal("missing capability admitted")
	}
	for _, c := range []identity.Command{{}, func() identity.Command { c, _ := identity.NewFeatureCommand(phonePasswordResetSpec()); return c }()} {
		if _, ok := c.PhonePasswordResetInputFeature(); ok {
			t.Fatal("plain/zero admitted as original custody")
		}
		if _, ok := c.PhonePasswordResetFeature(); ok {
			t.Fatal("plain/zero admitted as generated custody")
		}
		if _, _, _, _, ok := c.PhonePasswordResetInputCustody(); ok {
			t.Fatal("plain/zero disclosed original custody")
		}
		if _, _, _, _, ok := c.PhonePasswordResetCustody(); ok {
			t.Fatal("plain/zero disclosed generated custody")
		}
	}
}
