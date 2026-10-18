package reference

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	"github.com/faustbrian/go-identity/password"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/username"
)

func (f FeatureSet) selectedUsername() (*usernameState, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_username"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.username == nil {
		return nil, identity.UnavailableError{}
	}
	return s.features.username, nil
}

// UsernameSignup returns only the explicitly selected native email-plus-name
// registration owner. Calls retain startup, tenant and graph shutdown guards.
func (f FeatureSet) UsernameSignup() (password.SignupService, error) {
	u, err := f.selectedUsername()
	if err != nil {
		return nil, err
	}
	if u.signup == nil {
		return nil, identity.UnavailableError{}
	}
	return composedUsernameSignup{state: f.state, owner: u.signup}, nil
}

// UsernameRegistrationVerification returns the original username registration
// owner's confirmation and metadata-only recovery, independently of HTTP.
// Confirmation atomically consumes its original purpose-bound proof with the
// address transition. It never substitutes the email signup owner or signs in.
// Retained handles remain subject to graph startup, tenant and shutdown guards.
func (f FeatureSet) UsernameRegistrationVerification() (email.RegistrationVerificationService, error) {
	u, err := f.selectedUsername()
	if err != nil {
		return nil, err
	}
	if u.signup == nil {
		return nil, identity.UnavailableError{}
	}
	return composedUsernameSignup{state: f.state, owner: u.signup}, nil
}

// UsernameSignin returns the distinct native username/password workflow.
// The selected known-empty factor profile denies enrolled or unknown MFA state.
func (f FeatureSet) UsernameSignin() (password.SigninService, error) {
	u, err := f.selectedUsername()
	if err != nil {
		return nil, err
	}
	if u.signin == nil {
		return nil, identity.UnavailableError{}
	}
	return composedUsernameSignin{state: f.state, owner: u.signin}, nil
}

// UsernameAvailability returns the selected durable advisory owner. Each call
// is a separately metered primary observation, never a reservation or cache.
func (f FeatureSet) UsernameAvailability() (username.AvailabilityService, error) {
	u, err := f.selectedUsername()
	if err != nil {
		return nil, err
	}
	if u.available == nil {
		return nil, identity.UnavailableError{}
	}
	return composedUsernameAvailability{state: f.state, owner: u.available}, nil
}

// UsernameRenameService retains original native mutation/recovery and custody
// authentication for callers composing shared transport rate admission.
type UsernameRenameService interface {
	username.RenameService
	username.RenameRateSource
}

// UsernameRename returns the selected native protected self-rename owner.
// Original proof/key/session custody and current mutation authority are native;
// no application store, renewed proof or alternate session engine is accepted.
func (f FeatureSet) UsernameRename() (UsernameRenameService, error) {
	u, err := f.selectedUsername()
	if err != nil {
		return nil, err
	}
	if u.rename == nil {
		return nil, identity.UnavailableError{}
	}
	return composedUsernameRename{state: f.state, owner: u.rename}, nil
}

// UsernameSignupPreAuth returns the fixed original username-registration flow
// issuer. It never substitutes the email-signup or username-signin action.
func (f FeatureSet) UsernameSignupPreAuth() (PreAuthService, error) {
	u, err := f.selectedUsername()
	if err != nil {
		return nil, err
	}
	if u.signupPreauth == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPreAuth{state: f.state, issuer: u.signupPreauth}, nil
}

// UsernameSigninPreAuth returns the fixed original username-signin flow issuer.
// Retained handles remain subject to initialized graph and shutdown admission.
func (f FeatureSet) UsernameSigninPreAuth() (PreAuthService, error) {
	u, err := f.selectedUsername()
	if err != nil {
		return nil, err
	}
	if u.signinPreauth == nil {
		return nil, identity.UnavailableError{}
	}
	return composedPreAuth{state: f.state, issuer: u.signinPreauth}, nil
}

type composedUsernameSignup struct {
	state *storeState
	owner *passwordpg.SignupService
}

func (f composedUsernameSignup) Signup(ctx context.Context, r password.SignupRequest) (password.SignupResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return password.SignupResult{}, err
	}
	defer done()
	return f.owner.Signup(w, r)
}
func (f composedUsernameSignup) RecoverSignup(ctx context.Context, r password.SignupRecoveryRequest) (password.SignupResult, error) {
	q, _, err := r.Recovery.Bindings()
	if err != nil {
		return password.SignupResult{}, err
	}
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return password.SignupResult{}, err
	}
	defer done()
	return f.owner.RecoverSignup(w, r)
}
func (f composedUsernameSignup) SignupRateSource(ctx context.Context, r password.SignupAddressInput) (string, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return "", err
	}
	defer done()
	return f.owner.SignupRateSource(w, r)
}

func (f composedUsernameSignup) VerificationConfirm(ctx context.Context, r email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return email.VerificationConfirmResult{}, err
	}
	defer done()
	return f.owner.VerificationConfirm(w, r)
}

func (f composedUsernameSignup) VerificationRecover(ctx context.Context, r email.VerificationRecoveryRequest) (email.VerificationRecoveryResult, error) {
	q, err := r.Recovery.Bindings()
	if err != nil {
		return email.VerificationRecoveryResult{}, err
	}
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return email.VerificationRecoveryResult{}, err
	}
	defer done()
	return f.owner.VerificationRecover(w, r)
}

var _ email.RegistrationVerificationService = composedUsernameSignup{}

type composedUsernameSignin struct {
	state *storeState
	owner *passwordpg.SigninService
}

func (f composedUsernameSignin) Signin(ctx context.Context, r password.SigninRequest) (password.SigninResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return password.SigninResult{}, err
	}
	defer done()
	return f.owner.Signin(w, r)
}
func (f composedUsernameSignin) RecoverSignin(ctx context.Context, r password.SigninRecoveryRequest) (password.SigninResult, error) {
	q, _, err := r.Recovery.Bindings()
	if err != nil {
		return password.SigninResult{}, err
	}
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return password.SigninResult{}, err
	}
	defer done()
	return f.owner.RecoverSignin(w, r)
}
func (f composedUsernameSignin) SigninRateSource(ctx context.Context, r password.SigninRequest) (string, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return "", err
	}
	defer done()
	return f.owner.SigninRateSource(w, r)
}

type composedUsernameAvailability struct {
	state *storeState
	owner *passwordpg.UsernameAvailabilityService
}

func (f composedUsernameAvailability) Available(ctx context.Context, r username.AvailabilityRequest) (username.AvailabilityResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, identity.TenantID(r.TenantID))
	if err != nil {
		return username.AvailabilityResult{}, err
	}
	defer done()
	return f.owner.Available(w, r)
}

type composedUsernameRename struct {
	state *storeState
	owner *passwordpg.UsernameRenameService
}

func (f composedUsernameRename) Rename(ctx context.Context, r username.RenameRequest) (identity.CommandResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return f.owner.Rename(w, r)
}
func (f composedUsernameRename) RenameRateSource(ctx context.Context, r username.RenameRequest) (identity.UserID, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return "", err
	}
	defer done()
	return f.owner.RenameRateSource(w, r)
}
func (f composedUsernameRename) RenameRecover(ctx context.Context, q identity.RecoveryQuery, c authorization.DecisionContext) (identity.CommandResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return f.owner.RenameRecover(w, q, c)
}
