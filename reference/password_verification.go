package reference

import (
	"context"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/password"
)

// PasswordVerification returns explicitly selected bearer reauthentication.
// Calls require initialized graph custody and an allowed tenant; retained
// handles deny after Close. Native verification issues a bounded upstream proof,
// never creates/extends a session or automatically consumes the proof.
func (f FeatureSet) PasswordVerification() (password.VerificationService, error) {
	if err := f.passwordVerificationSelected(false); err != nil {
		return nil, err
	}
	return composedPasswordVerification{state: f.state}, nil
}

// CookiePasswordVerification returns the distinct synchronizer-protected native
// workflow. Missing cookie selection denies, with no tokenless bearer fallback.
// Obtaining either handle starts no IO and implicitly exposes no HTTP route.
func (f FeatureSet) CookiePasswordVerification() (password.CookieVerificationService, error) {
	if err := f.passwordVerificationSelected(true); err != nil {
		return nil, err
	}
	return composedCookiePasswordVerification{state: f.state}, nil
}

func (f FeatureSet) passwordVerificationSelected(cookie bool) error {
	s := f.state
	if s == nil {
		return identity.InvalidInputError{Field: "reference_password_verification"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passwordVerification == nil || s.features.passwordVerification.bearer == nil || cookie && s.features.passwordVerification.cookie == nil {
		return identity.UnavailableError{}
	}
	return nil
}

type composedPasswordVerification struct{ state *storeState }
type composedCookiePasswordVerification struct{ state *storeState }

func (f composedPasswordVerification) Verify(ctx context.Context, r password.VerificationRequest) (password.VerificationResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return password.VerificationResult{}, err
	}
	defer done()
	return f.state.features.passwordVerification.bearer.Verify(w, r)
}

func (f composedPasswordVerification) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.VerificationResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return password.VerificationResult{}, err
	}
	defer done()
	return f.state.features.passwordVerification.bearer.Recover(w, q, caller)
}

func (f composedCookiePasswordVerification) Verify(ctx context.Context, r password.CookieVerificationRequest) (password.VerificationResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.Request.TenantID)
	if err != nil {
		return password.VerificationResult{}, err
	}
	defer done()
	return f.state.features.passwordVerification.cookie.Verify(w, r)
}

func (f composedCookiePasswordVerification) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.VerificationResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return password.VerificationResult{}, err
	}
	defer done()
	return f.state.features.passwordVerification.cookie.Recover(w, q, caller)
}

var _ password.VerificationService = composedPasswordVerification{}
var _ password.CookieVerificationService = composedCookiePasswordVerification{}
