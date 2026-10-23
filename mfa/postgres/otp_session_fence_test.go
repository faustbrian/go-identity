package mfapostgres

import (
	"context"
	"errors"
	"testing"

	kernel "github.com/faustbrian/go-identity/postgres"
)

func TestOTPSessionFenceRequiresActualNativeRevokeWork(t *testing.T) {
	var work kernel.Work
	for _, state := range []OTPSessionFactorState{{}, {EnrollmentVersion: 1}, {AuthorityVersion: 1}, {EnrollmentVersion: 1, AuthorityVersion: 1}} {
		if err := RequireOTPSessionFactor(t.Context(), work, nil, "user", "AAAAAAAAAAAAAAAAAAAAAQ", state); err == nil {
			t.Fatal("OTP factor authority was accepted without registered revoke Work")
		}
	}
	valid := OTPSessionFactorState{EnrollmentVersion: 1, AuthorityVersion: 1}
	if err := RequireOTPSessionFactor(nil, work, nil, "user", "AAAAAAAAAAAAAAAAAAAAAQ", valid); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RequireOTPSessionFactor(ctx, work, nil, "user", "AAAAAAAAAAAAAAAAAAAAAQ", valid); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
}
