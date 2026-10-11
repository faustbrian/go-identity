package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
)

// PasswordSignin returns the selected native password-login and recovery owner.
// Obtaining a handle starts no IO or HTTP route. Every call requires initialized
// graph custody, an allowed tenant and the graph's bounded lifetime. Retained
// handles deny after Close, including historical recovery.
func (f FeatureSet) PasswordSignin() (password.SigninService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_password_signin"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passwordSignin == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPasswordSignin{state: s}, nil
}

type composedPasswordSignin struct{ state *storeState }

func (f composedPasswordSignin) Signin(ctx context.Context, r password.SigninRequest) (password.SigninResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return password.SigninResult{}, err
	}
	defer done()
	return f.state.features.passwordSignin.Signin(w, r)
}

func (f composedPasswordSignin) RecoverSignin(ctx context.Context, r password.SigninRecoveryRequest) (password.SigninResult, error) {
	q, _, err := r.Recovery.Bindings()
	if err != nil {
		return password.SigninResult{}, err
	}
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return password.SigninResult{}, err
	}
	defer done()
	return f.state.features.passwordSignin.RecoverSignin(w, r)
}

var _ password.SigninService = composedPasswordSignin{}
