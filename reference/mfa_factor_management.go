package reference

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// MFAFactorManagement returns separately selected native self-management.
// The current TOTP profile supports rename and explicitly configured sole-factor
// email-recovery removal; replacement remains unavailable. It selects no disable,
// HTTP routes, login or regeneration.
// Retained handles obey exact tenant and graph startup/drain/shutdown ownership.
func (f FeatureSet) MFAFactorManagement() (mfa.FactorManagementService, error) {
	if err := f.mfaEnrollmentSelected(); err != nil {
		return nil, err
	}
	if f.state.features.mfaEnrollment.manage == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMFAFactorManagement{state: f.state}, nil
}

type composedMFAFactorManagement struct{ state *storeState }

func (f composedMFAFactorManagement) FactorUpdate(ctx context.Context, r mfa.FactorUpdateRequest) (mfa.FactorUpdateResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.FactorUpdateResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.manage.FactorUpdate(w, r)
}
func (f composedMFAFactorManagement) RecoverFactorUpdate(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.FactorUpdateResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.FactorUpdateResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.manage.RecoverFactorUpdate(w, q, caller)
}
