package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func otpSigninMappingFixture(t testing.TB, anonymous, csrf bool) (identity.FeatureCommandSpec, session.Session) {
	t.Helper()
	record := otpRecordFixture(t, csrf)
	s, _ := record.Bindings()
	p, _ := record.OTPAuthentication().Bindings()
	b := revokeBinding()
	b.CommandID, b.TenantID, b.UserID = p.CommandID, s.TenantID, s.UserID
	b.RecordID, b.OperationID, b.SchemaID = "", "identity.otp.signin", "identity-otp-signin"
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted}
	if anonymous {
		b.UserID, b.AnonymousFlowID = "", "original-flow"
		op.SubjectRequirement = identity.FeatureSubjectAnonymousFlow
	}
	fields, err := OTPSigninSessionFields(record)
	if err != nil {
		t.Fatal(err)
	}
	return identity.FeatureCommandSpec{Binding: b, Operation: op, Fields: fields}, record
}

func TestOTPSigninMappingPreservesCompleteOriginalSession(t *testing.T) {
	for _, anonymous := range []bool{false, true} {
		for _, csrf := range []bool{false, true} {
			spec, original := otpSigninMappingFixture(t, anonymous, csrf)
			// Other fields are owned and exhaustively checked by the OTP adapter.
			spec.Fields = append(spec.Fields, identity.FeatureField{Name: "otp.custody", Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: []byte{1}}})
			command, err := identity.NewFeatureCommand(spec)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := OTPSigninSession(command)
			if err != nil {
				t.Fatal("complete original OTP session rejected", err)
			}
			a, _, _ := encodeRecord(original)
			b, _, _ := encodeRecord(restored)
			if !bytes.Equal(a, b) {
				t.Fatal("session/remember/authority/OTP/CSRF changed in command mapping")
			}
			// Every owned scalar is required, including false/zero discriminators.
			for i := range spec.Fields[:len(spec.Fields)-1] {
				changed := spec
				changed.Fields = append([]identity.FeatureField{}, spec.Fields[:i]...)
				changed.Fields = append(changed.Fields, spec.Fields[i+1:]...)
				cmd, err := identity.NewFeatureCommand(changed)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := OTPSigninSession(cmd); err == nil {
					t.Fatalf("omitted original field %s admitted", spec.Fields[i].Name)
				}
				changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
				changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureBool}
				if spec.Fields[i].Value.Kind == identity.FeatureBool {
					changed.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureText}
				}
				cmd, err = identity.NewFeatureCommand(changed)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := OTPSigninSession(cmd); err == nil {
					t.Fatalf("wrong scalar kind for %s admitted", spec.Fields[i].Name)
				}
			}
		}
	}
}

func TestPhoneOTPSigninMappingRetainsClosedPhoneOperation(t *testing.T) {
	spec, original := otpSigninMappingFixture(t, true, true)
	spec.Binding.OperationID, spec.Operation.OperationID = "identity.phone.signin", "identity.phone.signin"
	spec.Binding.SchemaID, spec.Operation.SchemaID = "identity.phone.signin.native-v1", "identity.phone.signin.native-v1"
	spec.Operation.Owner = "identity/phone"
	metadata, _ := original.OTPAuthentication().Bindings()
	if metadata.IdentifierKind != identity.IdentifierPhone {
		t.Fatal("fixture does not contain original phone authentication")
	}
	command, err := identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := OTPSigninSession(command)
	if err != nil {
		t.Fatal("closed phone OTP operation rejected", err)
	}
	before, _, _ := encodeRecord(original)
	after, _, _ := encodeRecord(restored)
	if !bytes.Equal(before, after) {
		t.Fatal("phone OTP command changed original session/authentication/CSRF/remember")
	}
	for i := range spec.Fields {
		if spec.Fields[i].Name == otpSessionPrefix+"otp.kind" {
			spec.Fields[i].Value = identity.FeatureValue{Kind: identity.FeatureText, Text: "email"}
		}
	}
	command, err = identity.NewFeatureCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OTPSigninSession(command); err == nil {
		t.Fatal("phone-owned signin accepted email authentication metadata")
	}
}

func TestOTPSigninMappingRejectsNoncanonicalScalars(t *testing.T) {
	spec, _ := otpSigninMappingFixture(t, false, true)
	for name, value := range map[string]identity.FeatureValue{
		"lookup.version":           {Kind: identity.FeatureUint64, Uint64: 1 << 32},
		"lookup.digest":            {Kind: identity.FeatureBytes, Bytes: []byte{1}},
		"remember.choice":          {Kind: identity.FeatureUint64, Uint64: 256},
		"otp.identifier-version":   {Kind: identity.FeatureUint64},
		"otp.verification-version": {Kind: identity.FeatureUint64},
		"otp.kind":                 {Kind: identity.FeatureText, Text: "username"},
		"otp.authenticated":        {Kind: identity.FeatureText, Text: "2026-10-09T00:00:00+00:00"},
		"otp.valid-until":          {Kind: identity.FeatureText, Text: "invalid"},
		"authentication.kind":      {Kind: identity.FeatureUint64, Uint64: uint64(session.AuthenticationVerified)},
		"csrf.key-version":         {Kind: identity.FeatureUint64, Uint64: 1 << 32},
		"csrf.digest":              {Kind: identity.FeatureBytes, Bytes: []byte{1}},
		"user.id":                  {Kind: identity.FeatureText, Text: "foreign"},
	} {
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
		found := false
		for i := range changed.Fields {
			if changed.Fields[i].Name == otpSessionPrefix+name {
				changed.Fields[i].Value, found = value, true
			}
		}
		if !found {
			t.Fatalf("missing fixture field %s", name)
		}
		command, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OTPSigninSession(command); err == nil {
			t.Fatalf("noncanonical %s admitted", name)
		}
	}
}

func FuzzOTPSigninMapping(f *testing.F) {
	f.Add(uint8(0), "invalid")
	f.Add(uint8(12), "phone")
	f.Add(uint8(30), "2026-10-09T00:00:00Z")
	spec, _ := otpSigninMappingFixture(f, true, true)
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
		record, err := OTPSigninSession(command)
		if err != nil {
			return
		}
		fields, err := OTPSigninSessionFields(record)
		if err != nil {
			t.Fatal("accepted record cannot be remapped", err)
		}
		changed.Fields = fields
		canonical, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		again, err := OTPSigninSession(canonical)
		a, _, _ := encodeRecord(record)
		b, _, _ := encodeRecord(again)
		if err != nil || !bytes.Equal(a, b) {
			t.Fatal("accepted record is not canonically stable", err)
		}
	})
}

func TestOTPSigninMappingRejectsForeignAndMixedProfiles(t *testing.T) {
	spec, _ := otpSigninMappingFixture(t, true, true)
	for _, change := range []func(*identity.FeatureCommandSpec){
		func(s *identity.FeatureCommandSpec) { s.Binding.CommandID = "BAQEBAQEBAQEBAQEBAQEBA" },
		func(s *identity.FeatureCommandSpec) { s.Binding.TenantID = "foreign" },
		func(s *identity.FeatureCommandSpec) { s.Operation.Owner = "identity/email" },
		func(s *identity.FeatureCommandSpec) {
			s.Fields = append(s.Fields, identity.FeatureField{Name: "session.result.unknown", Value: identity.FeatureValue{Kind: identity.FeatureBool}})
		},
	} {
		changed := spec
		changed.Fields = append([]identity.FeatureField{}, spec.Fields...)
		change(&changed)
		command, err := identity.NewFeatureCommand(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OTPSigninSession(command); err == nil {
			t.Fatal("foreign or mixed original OTP profile admitted")
		}
	}
	for _, record := range []session.Session{{}, testSession(t)} {
		if _, err := OTPSigninSessionFields(record); err == nil {
			t.Fatal("non-OTP record mapped as signin")
		}
	}
	if _, err := OTPSigninSession(identity.Command{}); err == nil {
		t.Fatal("zero command admitted")
	}
}
