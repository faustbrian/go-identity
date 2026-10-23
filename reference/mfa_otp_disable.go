package reference

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// MFAOTPDisable returns explicitly selected native OTP disable, not TOTP,
// factor-update or HTTP fallback. Every retained call obeys graph tenant,
// startup and shutdown ownership. Recovery returns original metadata only.
func (f FeatureSet) MFAOTPDisable() (mfa.DisableService, error) {
	if err := f.mfaOTPEnrollmentSelected(); err != nil {
		return nil, err
	}
	if f.state.features.mfaOTPEnrollment.disable == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMFAOTPDisable{state: f.state}, nil
}

type composedMFAOTPDisable struct{ state *storeState }

func (f composedMFAOTPDisable) Disable(ctx context.Context, r mfa.DisableRequest) (mfa.DisableResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.DisableResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.disable.Disable(w, r)
}

func (f composedMFAOTPDisable) RecoverDisable(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.DisableResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.DisableResult{}, err
	}
	defer done()
	return f.state.features.mfaOTPEnrollment.disable.RecoverDisable(w, q, caller)
}
