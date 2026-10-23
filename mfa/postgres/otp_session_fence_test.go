package mfapostgres

import (
	"context"
	"errors"
	"testing"

	identity "github.com/faustbrian/go-identity"
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

func TestOTPSessionFactorActionRequiresExactNativeProfile(t *testing.T) {
	owner := kernel.FeatureRegistration{Contributor: kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}, Operation: identity.FeatureOperation{Owner: "identity/mfa"}}
	for _, profile := range []struct{ operation, schema string }{
		{"identity.mfa.otp-send", "mfa-otp-step-up-send"},
		{"identity.mfa.otp-verify", "mfa-otp-step-up"},
		{"identity.mfa.factor-update", "mfa-factor-update"},
	} {
		binding := identity.CommandBinding{OperationID: profile.operation, SchemaID: profile.schema, SchemaVersion: 1}
		if !nativeOTPSessionFactorConsumer(binding, owner) {
			t.Fatal("explicit active OTP factor consumer rejected", profile.operation)
		}
		for _, bad := range []string{"mfa-otp-send", "mfa-otp-enrollment-confirm", "mfa-totp-step-up", "arbitrary"} {
			binding.SchemaID = bad
			if nativeOTPSessionFactorConsumer(binding, owner) {
				t.Fatal("OTP current factor accepted unrelated owner schema", bad)
			}
		}
		binding.SchemaID = profile.schema
		foreign := owner
		foreign.Contributor.Owner = "identity/otp/postgres"
		if nativeOTPSessionFactorConsumer(binding, foreign) {
			t.Fatal("foreign contributor acquired MFA factor checks")
		}
	}
}
