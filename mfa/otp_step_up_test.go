package mfa_test

import (
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func authenticatedOTPRequests(t *testing.T) (mfa.OtpSendRequest, mfa.OtpVerifyRequest) {
	t.Helper()
	original := enrollmentConfirmationFixture(t)
	send := otpSendFixture(t)
	send.TenantID, send.Caller = original.TenantID, original.Caller.Clone()
	send.Caller.Request.Action = "identity.mfa.otp-send"
	send.ContinuationID, send.PreAuthID, send.Proof, send.Cookie = "", "", capability.Proof{}, auth.BearerCredential{}
	send.Callback, send.Device, send.FactorID = "", "", original.FactorID
	send.StepUp = &mfa.OTPAuthenticatedStepUp{Session: original.Enrollment.Session, CSRFToken: original.Enrollment.CSRFToken, Purpose: "identity.mfa.factor-update"}
	verify := otpVerifyFixture(t)
	verify.TenantID, verify.Caller = original.TenantID, original.Caller.Clone()
	verify.Caller.Request.Action = "identity.mfa.otp-verify"
	verify.ContinuationID, verify.PreAuthID, verify.Proof, verify.Cookie = "", "", capability.Proof{}, auth.BearerCredential{}
	verify.Callback, verify.Device, verify.FactorID = "", "", original.FactorID
	verify.CommandID = "AAAAAAAAAAAAAAAAAAAAAw"
	copy := *send.StepUp
	copy.SendCommandID = "AAAAAAAAAAAAAAAAAAAABA"
	verify.StepUp = &copy
	return send, verify
}

// These are intrinsic public input checks, not proof of delivery, ownership,
// signature validation, current authority or atomic OTP/proof consumption.
func TestAuthenticatedOTPStepUpIsDisjointFromLoginAndEnrollment(t *testing.T) {
	send, verify := authenticatedOTPRequests(t)
	if err := send.Validate(); err != nil {
		t.Fatal("active-factor OTP send cannot reach its selected owner", err)
	}
	if err := verify.Validate(); err != nil {
		t.Fatal("active-factor OTP verification cannot reach its selected owner", err)
	}
	for _, mode := range []string{"enrollment", "login-flow", "login-cookie", "empty-session", "empty-csrf", "foreign-action", "empty-factor", "wrong-resource", "trust-device", "missing-send", "same-send", "invalid-send"} {
		t.Run(mode, func(t *testing.T) {
			candidate := verify
			step := *verify.StepUp
			candidate.StepUp, candidate.Caller = &step, verify.Caller.Clone()
			switch mode {
			case "enrollment":
				candidate.Enrollment = &mfa.OTPEnrollmentContext{Session: step.Session, CSRFToken: step.CSRFToken}
			case "login-flow":
				candidate.ContinuationID = "AAAAAAAAAAAAAAAAAAAABQ"
			case "login-cookie":
				candidate.Cookie = step.Session
			case "empty-session":
				step.Session = auth.BearerCredential{}
			case "empty-csrf":
				step.CSRFToken = session.CSRFToken{}
			case "foreign-action":
				step.Purpose = "identity.password.change"
			case "empty-factor":
				candidate.FactorID = ""
			case "wrong-resource":
				candidate.Caller.Request.Resource.ID = "other-user"
			case "trust-device":
				candidate.TrustDevice = true
			case "missing-send":
				step.SendCommandID = ""
			case "same-send":
				step.SendCommandID = candidate.CommandID
			case "invalid-send":
				step.SendCommandID = identity.CommandID("malformed")
			}
			if candidate.Validate() == nil {
				t.Fatal("mixed or unbound OTP step-up admitted")
			}
		})
	}
	copy := *send.StepUp
	copy.SendCommandID = verify.StepUp.SendCommandID
	send.StepUp = &copy
	if send.Validate() == nil {
		t.Fatal("fresh send accepted a caller-selected previous command")
	}
	login := otpVerifyFixture(t)
	login.StepUp = verify.StepUp
	if login.Validate() == nil {
		t.Fatal("login custody silently became authenticated action custody")
	}
}
