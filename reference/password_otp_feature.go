package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// PasswordOTP returns only explicitly selected password-origin secondary OTP
// send/completion. It selects no HTTP route, enrollment or alternate-method
// fallback. Calls retain graph startup, tenant, cancellation and shutdown
// admission; retained handles deny after Close, including historical recovery.
func (f FeatureSet) PasswordOTP() (mfa.OTPCompletionService, error) {
	s := f.state
	if s == nil {
		return nil, invalidPasswordOTPCompletion()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passwordOTP == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPasswordOTP{state: s}, nil
}

type composedPasswordOTP struct{ state *storeState }

func (f composedPasswordOTP) OtpSend(ctx context.Context, r mfa.OtpSendRequest) (mfa.OtpSendResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.OtpSendResult{}, err
	}
	defer done()
	return f.state.features.passwordOTP.OtpSend(w, r)
}

func (f composedPasswordOTP) OtpVerify(ctx context.Context, r mfa.OtpVerifyRequest) (mfa.OtpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.OtpVerifyResult{}, err
	}
	defer done()
	return f.state.features.passwordOTP.OtpVerify(w, r)
}

// OtpVerificationRateSource retains graph admission for read-only original
// quota metadata; it cannot extend native authority or bypass shutdown.
func (f composedPasswordOTP) OtpVerificationRateSource(ctx context.Context, r mfa.OtpVerifyRequest) (identity.UserID, string, time.Duration, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return "", "", 0, err
	}
	defer done()
	return f.state.features.passwordOTP.OtpVerificationRateSource(w, r)
}

func (f composedPasswordOTP) RecoverOtpSend(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.OtpSendResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.OtpSendResult{}, err
	}
	defer done()
	return f.state.features.passwordOTP.RecoverOtpSend(w, q, caller)
}

func (f composedPasswordOTP) RecoverOtpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.OtpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.OtpVerifyResult{}, err
	}
	defer done()
	return f.state.features.passwordOTP.RecoverOtpVerify(w, q, caller)
}

var _ mfa.OTPCompletionService = composedPasswordOTP{}
