package mfapostgres

import (
	"testing"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-identity/mfa"
)

func TestOTPActivePurposeSelectionDoesNotWidenDefault(t *testing.T) {
	state := &otpActiveState{}
	if !state.allows("identity.mfa.factor-update") || state.allows("identity.mfa.disable") || state.allows("identity.mfa.recovery-regenerate") {
		t.Fatal("default action profile changed")
	}
	state.config.AllowedPurposes = []auth.Purpose{"identity.mfa.disable"}
	if !state.allows("identity.mfa.disable") || state.allows("identity.mfa.factor-update") || state.allows("identity.mfa.recovery-regenerate") {
		t.Fatal("explicit disable selection admitted another action")
	}
}

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
