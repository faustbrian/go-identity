package reference

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	native "github.com/faustbrian/go-passkey/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

// PasskeyService is the guarded native existing-account reference profile.
// It owns no pool, transaction, protocol verifier or session store. Calls use
// the graph's initialized tenant and lifetime; retained handles deny after
// Close, including historical recovery. Browser parsing/origin/CSRF transport
// remains the caller's responsibility until HTTP is separately selected.
// Methods preserve original command custody and never remint ambiguous output.
type PasskeyService struct{ state *storeState }

func (PasskeyService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasskeyService(redacted)"))
}

// Passkeys returns only explicitly selected native passkey operations. It
// enables no route or browser UI and performs no IO. A handle can be retained
// before initialization, but operations require successful graph startup.
func (f FeatureSet) Passkeys() (*PasskeyService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_passkey"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passkey == nil {
		return nil, identity.UnavailableError{}
	}
	return &PasskeyService{state: s}, nil
}

func (f *PasskeyService) enter(ctx context.Context, tenant identity.TenantID) (context.Context, func(), error) {
	if f == nil || f.state == nil || f.state.features == nil || f.state.features.passkey == nil || tenant != f.state.features.passkey.tenant {
		return nil, nil, identity.ForbiddenError{}
	}
	return (composedPasswordReset{state: f.state}).enter(ctx, tenant)
}

func (f *PasskeyService) enterFixed(ctx context.Context) (context.Context, func(), error) {
	if f == nil || f.state == nil || f.state.features == nil || f.state.features.passkey == nil {
		return nil, nil, identity.ForbiddenError{}
	}
	return f.enter(ctx, f.state.features.passkey.tenant)
}

// RegistrationOptions consumes an exact fresh options proof in its real native
// command. Retain the resulting ceremony and obtain a distinct completion proof.
func (f *PasskeyService) RegistrationOptions(ctx context.Context, r native.RegistrationRequest) (webauthn.RegistrationOptions, error) {
	w, done, err := f.enter(ctx, r.Primary.TenantID)
	if err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	defer done()
	return f.state.features.passkey.enrollment.RegistrationOptions(w, r)
}

// KeyedRegistrationOptions delegates original request custody to the selected
// native request-key owner. Only its fresh committed winner can reveal options;
// retained retries return metadata and never recreate a challenge or proof.
func (f *PasskeyService) KeyedRegistrationOptions(ctx context.Context, r passkey.KeyedRegistrationOptionsRequest) (passkey.KeyedRegistrationOptionsResult, error) {
	w, done, err := f.enter(ctx, r.Primary.TenantID)
	if err != nil {
		return passkey.KeyedRegistrationOptionsResult{}, err
	}
	defer done()
	return f.state.features.passkey.enrollment.KeyedRegistrationOptions(w, r)
}

// RegistrationRateSource authenticates original enrollment custody for rate
// metadata only. It grants no permission to consume a proof or ceremony.
func (f *PasskeyService) RegistrationRateSource(ctx context.Context, r passkey.RegistrationCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	w, done, err := f.enter(ctx, r.Primary.TenantID)
	if err != nil {
		return passkey.CeremonyRateSource{}, err
	}
	defer done()
	return f.state.features.passkey.enrollment.RegistrationRateSource(w, r)
}

// Register verifies the raw authenticator response and commits all enrollment
// effects through the native owner's sole Work before exposing verification.
func (f *PasskeyService) Register(ctx context.Context, r native.RegistrationCompletion) (webauthn.VerifiedRegistration, error) {
	w, done, err := f.enter(ctx, r.Primary.TenantID)
	if err != nil {
		return webauthn.VerifiedRegistration{}, err
	}
	defer done()
	return f.state.features.passkey.enrollment.Register(w, r)
}

// RecoverEnrollment returns original outcome metadata, never a fresh challenge,
// credential, signed proof or permission to rerun an ambiguous command.
func (f *PasskeyService) RecoverEnrollment(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	w, done, err := f.enter(ctx, q.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return f.state.features.passkey.enrollment.RecoverEnrollment(w, q, caller)
}

// PrepareFlow delegates entropy and remember custody to the session owner.
// Retain this original preparation for IssueFlow and any metadata recovery.
func (f *PasskeyService) PrepareFlow(ctx context.Context, r session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error) {
	w, done, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	defer done()
	if err := w.Err(); err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	prepared, err := f.state.features.passkey.signin.PrepareFlow(r)
	if err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	if err := w.Err(); err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	return prepared, nil
}

// IssueFlow commits the original browser initiation, not authentication. Native
// preparation custody fixes the tenant; another preparation cannot replace it.
func (f *PasskeyService) IssueFlow(ctx context.Context, p session.PreparedPreAuthIssuance) (session.PreAuthIssueResult, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return session.PreAuthIssueResult{}, err
	}
	defer done()
	return f.state.features.passkey.signin.IssueFlow(w, p)
}

// AuthenticationOptions returns account-independent real resident UV options
// bound to the original identified browser attempt, never an account allowlist.
func (f *PasskeyService) AuthenticationOptions(ctx context.Context, r native.SigninRequest) (webauthn.AssertionOptions, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return webauthn.AssertionOptions{}, err
	}
	defer done()
	return f.state.features.passkey.signin.AuthenticationOptions(w, r)
}

// KeyedAuthenticationOptions retains the original identified browser command.
// Matching retries cannot reveal another challenge or renew original custody.
func (f *PasskeyService) KeyedAuthenticationOptions(ctx context.Context, r passkey.KeyedSigninOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return passkey.KeyedAssertionOptionsResult{}, err
	}
	defer done()
	return f.state.features.passkey.signin.KeyedAuthenticationOptions(w, r)
}

// KeyedDiscoverableAuthenticationOptions selects identifier-free original-key
// custody explicitly. It never tries identified signin after a denial.
func (f *PasskeyService) KeyedDiscoverableAuthenticationOptions(ctx context.Context, r passkey.KeyedDiscoverableOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return passkey.KeyedAssertionOptionsResult{}, err
	}
	defer done()
	return f.state.features.passkey.signin.KeyedDiscoverableAuthenticationOptions(w, r)
}

// SigninRateSource returns only the authenticated original identified rate
// dimension, original ceremony and immutable duration; it authenticates no user.
func (f *PasskeyService) SigninRateSource(ctx context.Context, r passkey.SigninCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return passkey.CeremonyRateSource{}, err
	}
	defer done()
	return f.state.features.passkey.signin.SigninRateSource(w, r)
}

// DiscoverableSigninRateSource returns the genuine original anonymous-flow
// rate dimension without turning a flow into a user or selecting an account.
func (f *PasskeyService) DiscoverableSigninRateSource(ctx context.Context, r passkey.DiscoverableCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return passkey.CeremonyRateSource{}, err
	}
	defer done()
	return f.state.features.passkey.signin.DiscoverableSigninRateSource(w, r)
}

// DiscoverableAuthenticationOptions starts identifier-free resident UV signin
// only when the graph's trusted authentication risk policy enables discovery.
// Tenant, RP and browser-flow authority remain fixed by the selected owners.
func (f *PasskeyService) DiscoverableAuthenticationOptions(ctx context.Context, r native.DiscoverableSigninRequest) (webauthn.AssertionOptions, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return webauthn.AssertionOptions{}, err
	}
	defer done()
	return f.state.features.passkey.signin.DiscoverableAuthenticationOptions(w, r)
}

// DiscoverableSignin resolves identity only through the genuine verified
// credential/handle pair and atomically finalizes the original browser flow
// and session. It never falls back to identified or another method's signin.
func (f *PasskeyService) DiscoverableSignin(ctx context.Context, r native.DiscoverableSigninCompletion) (native.SigninResult, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return native.SigninResult{}, err
	}
	defer done()
	return f.state.features.passkey.signin.DiscoverableSignin(w, r)
}

// Signin returns a usable credential only after genuine protocol verification
// and atomic native ceremony/flow/mapping/session finalization.
func (f *PasskeyService) Signin(ctx context.Context, r native.SigninCompletion) (native.SigninResult, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return native.SigninResult{}, err
	}
	defer done()
	return f.state.features.passkey.signin.Signin(w, r)
}

// RecoverSignin returns current-authorized original metadata only. It neither
// repeats verification nor redelivers a challenge, session or synchronizer.
func (f *PasskeyService) RecoverSignin(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (identity.CommandResult, error) {
	w, done, err := f.enter(ctx, q.TenantID)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return f.state.features.passkey.signin.RecoverSignin(w, q, caller)
}

// List returns bounded safe metadata authenticated by this selected passkey
// reader, not a fallback across password or other authentication methods.
func (f *PasskeyService) List(ctx context.Context, r native.InventoryRequest) (native.InventoryPage, error) {
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return native.InventoryPage{}, err
	}
	defer done()
	return f.state.features.passkey.inventory.List(w, r)
}

// Get reads this profile's actual issued session with current owner authority.
// No other reader is tried after denial and no authentication is renewed.
func (f *PasskeyService) Get(ctx context.Context, r session.GetRequest) (session.GetResult, error) {
	w, done, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return session.GetResult{}, err
	}
	defer done()
	return f.state.features.passkey.reader.Get(w, r)
}

// SignOut performs same-transaction cookie-CSRF self-revocation. Bearer input
// is not enabled by this profile. Transport clearing follows native outcomes.
func (f *PasskeyService) SignOut(ctx context.Context, r session.SignOutRequest, csrf session.CSRFToken) (session.SignOutResult, error) {
	w, done, err := f.enter(ctx, r.TenantID)
	if err != nil {
		return session.SignOutResult{}, err
	}
	defer done()
	return f.state.features.passkey.logout.SignOut(w, r, csrf)
}

// RecoverSignOut delegates exact historical revocation metadata and current
// disclosure policy to the original native coordinator, not another journal.
func (f *PasskeyService) RecoverSignOut(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (kernel.CommandRecord, error) {
	w, done, err := f.enter(ctx, q.TenantID)
	if err != nil {
		return kernel.CommandRecord{}, err
	}
	defer done()
	return f.state.features.passkey.revoke.RecoverRevokeOneCommand(w, q, caller)
}
