package mfapostgres

import "testing"

func TestOTPFactorUpdateRequiresActualSharedOwners(t *testing.T) {
	for _, pair := range []struct {
		enrollment *OTPEnrollmentService
		stepup     *OTPActiveStepUpService
	}{
		{}, {enrollment: &OTPEnrollmentService{}}, {stepup: &OTPActiveStepUpService{}},
	} {
		if owner, err := NewOTPFactorUpdateService(pair.enrollment, pair.stepup, FactorUpdateConfig{}); err == nil || owner != nil {
			t.Fatal("missing actual OTP ownership admitted")
		}
	}
}
