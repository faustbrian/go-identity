package mfapostgres

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
)

func TestOTPEnrollmentConfirmationRequiresNativeOwners(t *testing.T) {
	if service, err := NewOTPEnrollmentConfirmationService(nil, OTPEnrollmentConfirmationConfig{}); err == nil || service != nil {
		t.Fatal("unowned sender manufactured confirmation authority")
	}
	for _, service := range []*OTPEnrollmentConfirmationService{nil, {}} {
		out, err := service.OtpVerify(context.Background(), mfa.OtpVerifyRequest{})
		if err == nil || out.Outcome != 0 || out.Enrollment.ID != "" || out.Session.Token != (session.Token{}) {
			t.Fatal("unowned confirmation created a factor or session")
		}
	}
}
