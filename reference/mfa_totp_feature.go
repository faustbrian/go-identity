package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// MagicLinkTOTP returns the explicitly selected native TOTP completion owner.
// It neither exposes an HTTP route nor enrolls a factor or grants trusted-device
// policy. All calls retain graph startup, tenant, bounded lifetime and shutdown
// admission. Unselected/zero/closed graphs expose no handle; retained handles
// deny after Close. Recovery is original proof/code-free outcome reconciliation.
func (f FeatureSet) MagicLinkTOTP() (mfa.TOTPCompletionService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_totp"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.magicTOTP == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMagicTOTP{state: s}, nil
}

// PasswordTOTP returns only the explicitly selected password-primary completion
// owner. It preserves graph tenant/lifetime/shutdown admission and cannot expose
// routes, enroll factors or substitute a magic-link primary.
func (f FeatureSet) PasswordTOTP() (mfa.TOTPCompletionService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_password_totp"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passwordTOTP == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMagicTOTP{state: s, password: true}, nil
}

type composedMagicTOTP struct {
	state    *storeState
	password bool
}

func (f composedMagicTOTP) owner() *magicLinkTOTPService {
	if f.password {
		return f.state.features.passwordTOTP
	}
	return f.state.features.magicTOTP
}

func (f composedMagicTOTP) TotpVerify(ctx context.Context, request mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, request.TenantID)
	if err != nil {
		return mfa.TotpVerifyResult{}, err
	}
	defer done()
	return f.owner().TotpVerify(w, request)
}

func (f composedMagicTOTP) RecoverTotpVerify(ctx context.Context, query identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.TotpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, query.TenantID)
	if err != nil {
		return mfa.TotpVerifyResult{}, err
	}
	defer done()
	return f.owner().RecoverTotpVerify(w, query, caller)
}

// TotpVerificationRateSource returns only authenticated original subject,
// child identity and immutable signed lifetime for transport quotas. It retains
// graph startup/tenant/shutdown admission and performs no native debit, factor
// decryption, comparison, reservation, issuance or validity renewal.
func (f composedMagicTOTP) TotpVerificationRateSource(ctx context.Context, request mfa.TotpVerifyRequest) (identity.UserID, string, time.Duration, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, request.TenantID)
	if err != nil {
		return "", "", 0, err
	}
	defer done()
	return f.owner().TotpVerificationRateSource(w, request)
}

var _ mfa.TOTPCompletionService = composedMagicTOTP{}
