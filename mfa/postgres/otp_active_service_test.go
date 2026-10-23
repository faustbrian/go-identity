package mfapostgres

import (
	"testing"

	"github.com/faustbrian/go-identity/mfa"
)

func TestOTPActiveStepUpRequiresActualNativeOwners(t *testing.T) {
	if service, err := NewOTPActiveStepUpService(nil, OTPActiveStepUpConfig{}); err == nil || service != nil {
		t.Fatal("absent current primary, OTP or signed-evidence owners admitted")
	}
	for _, service := range []*OTPActiveStepUpService{nil, {}} {
		if out, err := service.OtpSend(t.Context(), mfa.OtpSendRequest{}); err == nil || out.CommandID != "" || out.ChallengeID != "" || out.Outcome != 0 {
			t.Fatal("unowned active service issued a code or command")
		}
		if out, err := service.OtpVerify(t.Context(), mfa.OtpVerifyRequest{}); err == nil || out.StepUpProof.Bindings().Proof.ID != "" || out.Outcome != 0 {
			t.Fatal("unowned active service issued factor evidence")
		}
	}
}
