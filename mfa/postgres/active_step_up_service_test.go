package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/mfa"
)

func TestActiveStepUpRequiresNativeCompositionAndExplicitVariant(t *testing.T) {
	if service, err := NewTOTPActiveStepUpService(nil, TOTPActiveStepUpConfig{}); err == nil || service != nil {
		t.Fatal("unconfigured active-factor verification admitted")
	}
	for _, service := range []*TOTPActiveStepUpService{nil, {}} {
		for _, ctx := range []context.Context{nil, t.Context()} {
			out, err := service.TotpVerify(ctx, mfa.TotpVerifyRequest{})
			if err == nil || out.StepUpProof.Bindings().Proof.ID != "" || out.Outcome != 0 {
				t.Fatal("unselected active-factor verification supplied proof")
			}
			lifetime, until, err := service.ActiveStepUpRateSource(ctx, mfa.TotpVerifyRequest{})
			if err == nil || lifetime != 0 || !until.IsZero() {
				t.Fatal("unselected step-up supplied quota metadata")
			}
		}
	}
}
