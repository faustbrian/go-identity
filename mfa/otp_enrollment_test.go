package mfa

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
)

func TestOTPEnrollmentRequiresExplicitBoundRecipientSelection(t *testing.T) {
	r := enrollmentRequestFixture()
	r.FactorPolicy.Method = "otp"
	if r.Validate() == nil {
		t.Fatal("OTP enrollment inferred a delivery recipient")
	}
	r.OTP = &OTPEnrollmentSelection{Channel: delivery.ChannelEmail, IdentifierID: "verified-email"}
	if err := r.Validate(); err != nil {
		t.Fatal("explicit OTP enrollment input denied", err)
	}
	for _, change := range []func(*OTPEnrollmentSelection){
		func(s *OTPEnrollmentSelection) { s.Channel = 0 },
		func(s *OTPEnrollmentSelection) { s.Channel = 255 },
		func(s *OTPEnrollmentSelection) { s.IdentifierID = "" },
		func(s *OTPEnrollmentSelection) { s.IdentifierID = "unbounded recipient@example.test" },
	} {
		copy := *r.OTP
		change(&copy)
		bad := r
		bad.OTP = &copy
		if bad.Validate() == nil {
			t.Fatal("unbounded or implicit OTP recipient admitted")
		}
	}
	r.FactorPolicy.Method = "totp"
	if r.Validate() == nil {
		t.Fatal("OTP recipient smuggled into another factor method")
	}
	r.OTP = nil
	if r.Validate() != nil {
		t.Fatal("existing TOTP enrollment contract changed")
	}
	r.FactorPolicy.Method = "otp"
	r.OTP = &OTPEnrollmentSelection{Channel: delivery.ChannelSMS, IdentifierID: identity.IdentifierID("verified-phone")}
	if r.Validate() != nil {
		t.Fatal("intrinsic SMS selection mistaken for live recipient/policy admission")
	}
}
