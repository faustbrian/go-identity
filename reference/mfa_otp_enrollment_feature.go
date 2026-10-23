package reference

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func (f FeatureSet) mfaOTPEnrollmentSelected() error {
	s := f.state
	if s == nil {
		return identity.InvalidInputError{Field: "reference_mfa_otp_enrollment"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.mfaOTPEnrollment == nil {
		return identity.UnavailableError{}
	}
	return nil
}

// MFAOTPEnrollment returns explicitly selected native pending enrollment. Fresh
// proof, original session/CSRF, current verified recipient and risk are enforced
// by its native owners. Enable alone never activates a factor or issues a login
// session. Calls retain graph startup, tenant, cancellation and Close guards.
// Recovery returns original metadata without revealing recovery codes again.
func (f FeatureSet) MFAOTPEnrollment() (mfa.EnrollmentService, error) {
	if err := f.mfaOTPEnrollmentSelected(); err != nil {
		return nil, err
	}
	return composedMFAOTPEnrollment{state: f.state}, nil
}

// MFAOTPEnrollmentConfirmation returns purpose-bound sending and confirmation
// for the selected pending enrollment, not password-login completion. Codes are
// delivered by the selected worker/sender. Confirmation issues no login session;
// unknown outcomes recover through the original command without a second send.
// This handle selects no HTTP routes and remains unusable after graph Close.
func (f FeatureSet) MFAOTPEnrollmentConfirmation() (mfa.OTPCompletionService, error) {
	if err := f.mfaOTPEnrollmentSelected(); err != nil {
		return nil, err
	}
	return composedMFAOTPEnrollment{state: f.state}, nil
}

type composedMFAOTPEnrollment struct{ state *storeState }

func (f composedMFAOTPEnrollment) Enable(ctx context.Context, r mfa.EnableRequest) (mfa.EnableResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.EnableResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.enable.Enable(w, r)
}

func (f composedMFAOTPEnrollment) RecoverEnable(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.EnableResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.EnableResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.enable.RecoverEnable(w, q, caller)
}

func (f composedMFAOTPEnrollment) OtpSend(ctx context.Context, r mfa.OtpSendRequest) (mfa.OtpSendResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.OtpSendResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.send.OtpSend(w, r)
}

func (f composedMFAOTPEnrollment) RecoverOtpSend(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.OtpSendResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.OtpSendResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.send.RecoverOtpSend(w, q, caller)
}

func (f composedMFAOTPEnrollment) OtpVerify(ctx context.Context, r mfa.OtpVerifyRequest) (mfa.OtpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.OtpVerifyResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.confirm.OtpVerify(w, r)
}

func (f composedMFAOTPEnrollment) RecoverOtpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.OtpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.OtpVerifyResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.confirm.RecoverOtpVerify(w, q, caller)
}
