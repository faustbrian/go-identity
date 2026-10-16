package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/email"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/password"
)

// PasswordSignup returns the selected native registration/recovery owner.
// Calls retain initialized graph, tenant and shutdown admission. Registration
// returns a neutral acknowledgement and never issues a session in this profile.
func (f FeatureSet) PasswordSignup() (password.SignupService, error) {
	if err := f.registrationSelected(); err != nil {
		return nil, err
	}
	return composedPasswordSignup{state: f.state}, nil
}

// RegistrationVerification returns the same native owner's confirmation and
// metadata-only recovery ports. Confirmation atomically consumes the original
// proof with the protected address transition; it does not issue a session.
func (f FeatureSet) RegistrationVerification() (email.RegistrationVerificationService, error) {
	if err := f.registrationSelected(); err != nil {
		return nil, err
	}
	return composedPasswordSignup{state: f.state}, nil
}

func (f FeatureSet) registrationSelected() error {
	s := f.state
	if s == nil {
		return identity.InvalidInputError{Field: "reference_password_signup"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passwordSignup == nil {
		return identity.UnavailableError{}
	}
	return nil
}

type composedPasswordSignup struct{ state *storeState }

func (f composedPasswordSignup) Signup(ctx context.Context, r password.SignupRequest) (password.SignupResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return password.SignupResult{}, err
	}
	defer done()
	return f.state.features.passwordSignup.Signup(w, r)
}

func (f composedPasswordSignup) RecoverSignup(ctx context.Context, r password.SignupRecoveryRequest) (password.SignupResult, error) {
	q, _, err := r.Recovery.Bindings()
	if err != nil {
		return password.SignupResult{}, err
	}
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return password.SignupResult{}, err
	}
	defer done()
	return f.state.features.passwordSignup.RecoverSignup(w, r)
}

// SignupRateSource exposes only native address normalization under graph
// lifetime admission; no account lookup or user-selection callback is invoked.
func (f composedPasswordSignup) SignupRateSource(ctx context.Context, input password.SignupAddressInput) (string, error) {
	w, done, err := f.state.enterFeature(ctx, true)
	if err != nil {
		return "", err
	}
	defer done()
	return f.state.features.passwordSignup.SignupRateSource(w, input)
}

func (f composedPasswordSignup) VerificationConfirm(ctx context.Context, r email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return email.VerificationConfirmResult{}, err
	}
	defer done()
	return f.state.features.passwordSignup.VerificationConfirm(w, r)
}

func (f composedPasswordSignup) VerificationRecover(ctx context.Context, r email.VerificationRecoveryRequest) (email.VerificationRecoveryResult, error) {
	q, err := r.Recovery.Bindings()
	if err != nil {
		return email.VerificationRecoveryResult{}, err
	}
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return email.VerificationRecoveryResult{}, err
	}
	defer done()
	return f.state.features.passwordSignup.VerificationRecover(w, r)
}

// RegistrationVerificationRateSource authenticates original grant custody
// through the native owner before exposing its bounded rate-budget dimensions.
func (f composedPasswordSignup) RegistrationVerificationRateSource(ctx context.Context, proof capability.Proof, callback string, caller authorization.DecisionContext) (identity.UserID, string, time.Duration, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, identity.TenantID(caller.Request.Tenant))
	if err != nil {
		return "", "", 0, err
	}
	defer done()
	return f.state.features.passwordSignup.RegistrationVerificationRateSource(w, proof, callback, caller)
}

var _ passwordhttp.SignupService = composedPasswordSignup{}
var _ email.RegistrationVerificationService = composedPasswordSignup{}

// RegistrationVerificationSignin returns only the independently selected native
// original-browser registration confirmation/signin profile. Default signup,
// managed-address confirmation, scanner inspection and HTTP remain unchanged.
// Calls retain graph lifetime/tenant admission; recovery is metadata-only.
func (f FeatureSet) RegistrationVerificationSignin() (email.RegistrationVerificationSigninService, error) {
	if err := f.registrationSelected(); err != nil {
		return nil, err
	}
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	if f.state.features.verificationSignin == nil {
		return nil, identity.UnavailableError{}
	}
	return composedVerificationSignin{state: f.state}, nil
}

type composedVerificationSignin struct{ state *storeState }

func (f composedVerificationSignin) VerificationConfirmAndSignin(ctx context.Context, r email.VerificationSigninRequest) (email.VerificationSigninResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.Confirmation.TenantID)
	if err != nil {
		return email.VerificationSigninResult{}, err
	}
	defer done()
	return f.state.features.verificationSignin.VerificationConfirmAndSignin(w, r)
}

func (f composedVerificationSignin) VerificationSigninRecover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return f.state.features.verificationSignin.VerificationSigninRecover(w, q, caller)
}
