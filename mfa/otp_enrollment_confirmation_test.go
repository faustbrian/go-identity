package mfa_test

import (
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func TestOTPEnrollmentSendAndConfirmationAreDisjointFromLogin(t *testing.T) {
	source := enrollmentConfirmationFixture(t)
	send := otpSendFixture(t)
	send.TenantID = source.TenantID
	send.ContinuationID, send.PreAuthID, send.Proof, send.Cookie = "", "", capability.Proof{}, auth.BearerCredential{}
	send.Callback, send.Device = "", ""
	send.Caller = source.Caller
	send.Caller.Request.Action = "identity.mfa.otp-send"
	send.Enrollment = &mfa.OTPEnrollmentContext{Session: source.Enrollment.Session, CSRFToken: source.Enrollment.CSRFToken}
	if err := send.Validate(); err != nil {
		t.Fatal("authenticated OTP enrollment send denied", err)
	}
	verify := otpVerifyFixture(t)
	verify.TenantID = source.TenantID
	verify.ContinuationID, verify.PreAuthID, verify.Proof, verify.Cookie = "", "", capability.Proof{}, auth.BearerCredential{}
	verify.Callback, verify.Device = "", ""
	verify.FactorID, verify.Caller = source.FactorID, source.Caller
	verify.Caller.Request.Action = "identity.mfa.otp-verify"
	verify.Enrollment = &mfa.OTPEnrollmentContext{Session: source.Enrollment.Session, CSRFToken: source.Enrollment.CSRFToken}
	if err := verify.Validate(); err != nil {
		t.Fatal("authenticated OTP enrollment confirmation denied", err)
	}
	for _, change := range []func(*mfa.OtpVerifyRequest){
		func(r *mfa.OtpVerifyRequest) { r.FactorID = "" },
		func(r *mfa.OtpVerifyRequest) { r.Enrollment.Session = auth.BearerCredential{} },
		func(r *mfa.OtpVerifyRequest) { r.Enrollment.CSRFToken = session.CSRFToken{} },
		func(r *mfa.OtpVerifyRequest) { r.ContinuationID = "AwMDAwMDAwMDAwMDAwMDAw" },
		func(r *mfa.OtpVerifyRequest) { r.Cookie = auth.NewBearerCredential(source.Enrollment.Session.Token()) },
		func(r *mfa.OtpVerifyRequest) { r.Caller.Request.Subject.Kind = authorization.SubjectServiceAccount },
	} {
		bad := verify
		custody := *verify.Enrollment
		bad.Enrollment = &custody
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("missing or mixed OTP enrollment custody admitted")
		}
	}
	login := otpVerifyFixture(t)
	login.FactorID = source.FactorID
	if login.Validate() == nil {
		t.Fatal("login selected a new factor instead of original send custody")
	}
	// These are borrowed synchronizers, not one-use verification consumption.
	if _, err := source.Enrollment.CSRFToken.Reveal(); err != nil {
		t.Fatal("structural OTP validation consumed original synchronizer")
	}
}
