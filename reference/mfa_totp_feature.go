package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
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
	state        *storeState
	password     bool
	verification bool
	username     bool
	phone        bool
}

// PhoneTOTP returns only the explicitly composed verified-phone/password TOTP
// completion owner. It cannot select email/username or a weaker factor. Graph
// startup, tenant, deadline and shutdown admission also apply to retained handles.
func (f FeatureSet) PhoneTOTP() (mfa.TOTPCompletionService, error) {
	s, err := f.selectedPhoneSignin()
	if err != nil {
		return nil, err
	}
	if s.totp == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMagicTOTP{state: f.state, phone: true}, nil
}

// UsernameTOTP returns only the explicitly selected username-origin TOTP owner.
// It retains graph tenant, lifetime and shutdown guards and cannot select another
// original primary, enroll factors or silently fall back to weaker methods.
func (f FeatureSet) UsernameTOTP() (mfa.TOTPCompletionService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_username_totp"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.username == nil || s.features.username.totp == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMagicTOTP{state: s, username: true}, nil
}

// VerificationTOTP returns only explicitly selected verification-origin TOTP
// completion. It cannot consume a magic link/password primary or select HTTP,
// enrollment, recovery codes or trusted devices. Graph lifetime and tenant
// admission remain mandatory; retained handles deny after Close.
func (f FeatureSet) VerificationTOTP() (mfa.TOTPCompletionService, error) {
	s := f.state
	if s == nil {
		return nil, invalidTOTPCompletion()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.verificationTOTP == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMagicTOTP{state: s, verification: true}, nil
}

func (f composedMagicTOTP) owner() *magicLinkTOTPService {
	if f.phone {
		return f.state.features.phoneSignin.totp
	}
	if f.username {
		return f.state.features.username.totp
	}
	if f.verification {
		return f.state.features.verificationTOTP
	}
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
