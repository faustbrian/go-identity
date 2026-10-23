package postgres

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func TestActiveOTPPrimaryRejectsAbsentCurrentSessionBeforePreparation(t *testing.T) {
	command, err := identity.NewCommandID()
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []*PasswordActiveTOTPPrimarySource{nil, {}} {
		primary, current, err := source.PrepareOTPSend(t.Context(), mfa.OtpSendRequest{}, command)
		if err == nil || primary != nil || current.Authenticated {
			t.Fatal("unowned OTP send returned session custody")
		}
		primary, current, err = source.PrepareOTPVerify(t.Context(), mfa.OtpVerifyRequest{})
		if err == nil || primary != nil || current.Authenticated {
			t.Fatal("unowned OTP verification returned session custody")
		}
		if primary, err := source.RestoreOTPSend(t.Context(), mfa.OtpSendRequest{}, command, []byte("{}")); err == nil || primary != nil {
			t.Fatal("unowned OTP send restored session custody")
		}
		if primary, err := source.RestoreOTPVerify(t.Context(), mfa.OtpVerifyRequest{}, []byte("{}")); err == nil || primary != nil {
			t.Fatal("unowned OTP verify restored session custody")
		}
	}
}

func TestOTPActionSessionCustodyRequiresExactSelectedSchema(t *testing.T) {
	for _, profile := range []struct{ operation, schema string }{
		{"identity.mfa.otp-send", "mfa-otp-step-up-send"},
		{"identity.mfa.otp-verify", "mfa-otp-step-up"},
	} {
		t.Run(profile.operation, func(t *testing.T) {
			g, input := mfaActionSessionFixture(t)
			p, _ := input.Command.Feature()
			bearer, _ := input.Command.SessionToken()
			p.Binding.OperationID, p.Binding.SchemaID = profile.operation, profile.schema
			p.Operation.OperationID, p.Operation.SchemaID = profile.operation, profile.schema
			var err error
			input.Command, err = identity.NewFeatureSessionCommand(p, bearer)
			if err != nil || g.originalInput(input) != nil {
				t.Fatal("exact active OTP custody rejected", err)
			}
			for _, schema := range []string{"mfa-otp-send", "mfa-otp-enrollment-confirm", "mfa-totp-step-up"} {
				p.Binding.SchemaID, p.Operation.SchemaID = schema, schema
				input.Command, err = identity.NewFeatureSessionCommand(p, bearer)
				if err != nil {
					t.Fatal(err)
				}
				if g.originalInput(input) == nil {
					t.Fatal("active OTP borrowed another profile's session custody", schema)
				}
			}
		})
	}
}
