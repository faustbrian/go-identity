package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// PasswordRecovery returns only explicitly selected password-primary recovery
// completion. Native calls retain graph startup/tenant/lifetime and shutdown
// admission. It enables neither HTTP nor factor enrollment or TOTP fallback.
func (f FeatureSet) PasswordRecovery() (mfa.RecoveryCompletionService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_password_recovery"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passwordRecovery == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPasswordRecovery{state: s}, nil
}

type composedPasswordRecovery struct{ state *storeState }

func (f composedPasswordRecovery) RecoveryUse(ctx context.Context, r mfa.RecoveryUseRequest) (mfa.RecoveryUseResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.RecoveryUseResult{}, err
	}
	defer done()
	return f.state.features.passwordRecovery.RecoveryUse(w, r)
}

func (f composedPasswordRecovery) RecoverRecoveryUse(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (mfa.RecoveryUseResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return mfa.RecoveryUseResult{}, err
	}
	defer done()
	return f.state.features.passwordRecovery.RecoverRecoveryUse(w, q, caller)
}

func (f composedPasswordRecovery) RecoveryVerificationRateSource(ctx context.Context, r mfa.RecoveryUseRequest) (identity.UserID, string, time.Duration, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return "", "", 0, err
	}
	defer done()
	return f.state.features.passwordRecovery.RecoveryVerificationRateSource(w, r)
}

var _ mfa.RecoveryCompletionService = composedPasswordRecovery{}
