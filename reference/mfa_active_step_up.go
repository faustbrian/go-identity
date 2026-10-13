package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// MFAActiveStepUp returns explicitly selected native authenticated TOTP proof
// issuance. It exposes no route, creates no session and accepts no login or
// enrollment fallback. Retained handles obey graph startup/tenant/shutdown
// ownership; code-free recovery cannot redeliver factor proof.
func (f FeatureSet) MFAActiveStepUp() (mfa.TOTPCompletionService, error) {
	if err := f.mfaEnrollmentSelected(); err != nil {
		return nil, err
	}
	if f.state.features.mfaEnrollment.stepup == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMFAActiveStepUp{state: f.state}, nil
}

type composedMFAActiveStepUp struct{ state *storeState }

// ActiveStepUpRateSource exposes native original cookie/factor quota custody
// under the same selected graph lifetime; it does not issue a proof.
func (f composedMFAActiveStepUp) ActiveStepUpRateSource(ctx context.Context, r mfa.TotpVerifyRequest) (time.Duration, time.Time, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return 0, time.Time{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.stepup.ActiveStepUpRateSource(w, r)
}

// MFARecoveryRegeneration returns separately selected native whole-set
// replacement with fresh-factor proof consumption and session revocation.
// Retained handles obey graph startup/tenant/shutdown guards; recovery is
// metadata-only and cannot redeliver replacement codes. This selects no route.
func (f FeatureSet) MFARecoveryRegeneration() (mfa.RecoveryRegenerationService, error) {
	if err := f.mfaEnrollmentSelected(); err != nil {
		return nil, err
	}
	if f.state.features.mfaEnrollment.regenerate == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMFARecoveryRegeneration{state: f.state}, nil
}

type composedMFARecoveryRegeneration struct{ state *storeState }

func (f composedMFARecoveryRegeneration) RecoveryRegenerate(ctx context.Context, r mfa.RecoveryRegenerateRequest) (mfa.RecoveryRegenerateResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.RecoveryRegenerateResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.regenerate.RecoveryRegenerate(w, r)
}
func (f composedMFARecoveryRegeneration) RecoverRecoveryRegenerate(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.RecoveryRegenerateResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.RecoveryRegenerateResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.regenerate.RecoverRecoveryRegenerate(w, q, caller)
}

func (f composedMFAActiveStepUp) TotpVerify(ctx context.Context, r mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.TotpVerifyResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.stepup.TotpVerify(w, r)
}
func (f composedMFAActiveStepUp) RecoverTotpVerify(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.TotpVerifyResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.TotpVerifyResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.stepup.RecoverTotpVerify(w, q, caller)
}
