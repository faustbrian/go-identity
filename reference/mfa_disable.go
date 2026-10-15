package reference

import (
	"context"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// MFADisable returns separately selected native disable. It selects neither
// factor-update nor HTTP routes. Calls borrow exact tenant graph lifecycle;
// startup/drain/shutdown gates apply to retained handles on every invocation.
func (f FeatureSet) MFADisable() (mfa.DisableService, error) {
	if err := f.mfaEnrollmentSelected(); err != nil {
		return nil, err
	}
	if f.state.features.mfaEnrollment.disable == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMFADisable{state: f.state}, nil
}

type composedMFADisable struct{ state *storeState }

func (f composedMFADisable) Disable(ctx context.Context, r mfa.DisableRequest) (mfa.DisableResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.DisableResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.disable.Disable(w, r)
}

func (f composedMFADisable) RecoverDisable(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.DisableResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.DisableResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.disable.RecoverDisable(w, q, caller)
}
