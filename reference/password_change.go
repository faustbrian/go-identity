package reference

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
)

// PasswordChange returns the selected native keyed bearer replacement workflow.
// Calls require initialized graph custody and an allowed tenant. The sole native
// transaction owns proof consumption, password replacement and session effects;
// this port does not retry, sign proofs or create another journal.
func (f FeatureSet) PasswordChange() (password.ChangeService, error) {
	if err := f.passwordChangeSelected(false); err != nil {
		return nil, err
	}
	return composedPasswordChange{state: f.state}, nil
}

// CookiePasswordChange returns the distinct native CSRF-protected workflow.
// Missing cookie selection denies without bearer fallback. Retained handles
// deny after Close; obtaining a handle exposes no HTTP route and performs no IO.
func (f FeatureSet) CookiePasswordChange() (password.CookieChangeService, error) {
	if err := f.passwordChangeSelected(true); err != nil {
		return nil, err
	}
	return composedCookiePasswordChange{state: f.state}, nil
}

func (f FeatureSet) passwordChangeSelected(cookie bool) error {
	s := f.state
	if s == nil {
		return identity.InvalidInputError{Field: "reference_password_change"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passwordChange == nil || s.features.passwordChange.bearer == nil || cookie && s.features.passwordChange.cookie == nil {
		return identity.UnavailableError{}
	}
	return nil
}

type composedPasswordChange struct{ state *storeState }
type composedCookiePasswordChange struct{ state *storeState }

func (f composedPasswordChange) Change(ctx context.Context, r password.ChangeRequest) (password.ChangeResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return password.ChangeResult{}, err
	}
	defer done()
	return f.state.features.passwordChange.bearer.Change(w, r)
}

func (f composedPasswordChange) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.ChangeResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return password.ChangeResult{}, err
	}
	defer done()
	return f.state.features.passwordChange.bearer.Recover(w, q, caller)
}

func (f composedCookiePasswordChange) Change(ctx context.Context, r password.CookieChangeRequest) (password.ChangeResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.Request.TenantID)
	if err != nil {
		return password.ChangeResult{}, err
	}
	defer done()
	return f.state.features.passwordChange.cookie.Change(w, r)
}

func (f composedCookiePasswordChange) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.ChangeResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return password.ChangeResult{}, err
	}
	defer done()
	return f.state.features.passwordChange.cookie.Recover(w, q, caller)
}

var _ password.ChangeService = composedPasswordChange{}
var _ password.CookieChangeService = composedCookiePasswordChange{}
