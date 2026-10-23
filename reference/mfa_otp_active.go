package reference

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// MFAOTPActiveStepUp returns explicitly selected authenticated OTP sending and
// action-proof verification, not enrollment/login or HTTP. Retained handles
// obey graph startup, tenant, cancellation and Close ownership. Recovery is
// metadata-only and never redelivers a code or factor proof.
func (f FeatureSet) MFAOTPActiveStepUp() (mfa.OTPCompletionService, error) {
	if err := f.mfaOTPEnrollmentSelected(); err != nil {
		return nil, err
	}
	if f.state.features.mfaOTPEnrollment.active == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMFAOTPActive{state: f.state}, nil
}

type composedMFAOTPActive struct{ state *storeState }

// MFAOTPFactorManagement returns explicitly selected OTP factor rename. It
// exposes no TOTP fallback, removal, disable, replacement or HTTP routes.
// Retained handles obey the graph's tenant, startup and shutdown lifetime.
func (f FeatureSet) MFAOTPFactorManagement() (mfa.FactorManagementService, error) {
	if err := f.mfaOTPEnrollmentSelected(); err != nil {
		return nil, err
	}
	if f.state.features.mfaOTPEnrollment.manage == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMFAOTPManagement{state: f.state}, nil
}

type composedMFAOTPManagement struct{ state *storeState }

func (f composedMFAOTPManagement) FactorUpdate(ctx context.Context, r mfa.FactorUpdateRequest) (mfa.FactorUpdateResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.FactorUpdateResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.manage.FactorUpdate(w, r)
}
func (f composedMFAOTPManagement) RecoverFactorUpdate(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.FactorUpdateResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.FactorUpdateResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.manage.RecoverFactorUpdate(w, q, caller)
}

func (f composedMFAOTPActive) OtpSend(ctx context.Context, r mfa.OtpSendRequest) (mfa.OtpSendResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.OtpSendResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.active.OtpSend(w, r)
}
func (f composedMFAOTPActive) OtpVerify(ctx context.Context, r mfa.OtpVerifyRequest) (mfa.OtpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.OtpVerifyResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.active.OtpVerify(w, r)
}
func (f composedMFAOTPActive) RecoverOtpSend(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.OtpSendResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.OtpSendResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.active.RecoverOtpSend(w, q, caller)
}
func (f composedMFAOTPActive) RecoverOtpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.OtpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.OtpVerifyResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.active.RecoverOtpVerify(w, q, caller)
}
