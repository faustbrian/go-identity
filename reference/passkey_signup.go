package reference

import (
	"context"
	"fmt"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
	native "github.com/faustbrian/go-passkey/postgres"
	webauthn "github.com/faustbrian/go-webauthn"
)

// PasskeySignupConfiguration selects native prospective-account signup without
// an email, password or caller-supplied account. Flow is a distinct original
// browser intent for identity.passkey.register-verify; its Clock and Risk's
// Evaluation must be absent for graph injection. Flow policy matches Session's
// execution policy. Protocol, RP, issuer, CSRF, protected counters and optional
// request-key custody come from the enclosing PasskeyConfiguration. Startup
// borrows immutable configuration; enabling signup exposes no HTTP routes.
type PasskeySignupConfiguration struct {
	Flow session.PreAuthIssuerConfig
	Risk risk.ProtectedProviderAdmissionCustodyConfig
}

func (PasskeySignupConfiguration) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("reference.PasskeySignupConfiguration(redacted)"))
}

// MarshalJSON denies implicit configuration and key export.
func (PasskeySignupConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText denies implicit configuration and key export.
func (PasskeySignupConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

func (f *PasskeyService) enterSignup(ctx context.Context) (context.Context, func(), *native.SignupService, error) {
	if f == nil || f.state == nil || f.state.features == nil || f.state.features.passkey == nil || f.state.features.passkey.signup == nil {
		return nil, nil, nil, identity.UnavailableError{}
	}
	w, done, err := f.enterFixed(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	owner := f.state.features.passkey.signup
	if owner == nil {
		done()
		return nil, nil, nil, identity.UnavailableError{}
	}
	return w, done, owner, nil
}

// PrepareSignupFlow prepares the signup session owner's original entropy and
// remember choice. Tenant and live graph admission precede native preparation.
func (f *PasskeyService) PrepareSignupFlow(ctx context.Context, r session.PreAuthPrepareInput) (session.PreparedPreAuthIssuance, error) {
	w, done, owner, err := f.enterSignup(ctx)
	if err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	defer done()
	if err := w.Err(); err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	prepared, err := owner.PrepareFlow(r)
	if err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	if err := w.Err(); err != nil {
		return session.PreparedPreAuthIssuance{}, err
	}
	return prepared, nil
}

// IssueSignupFlow persists only the original anonymous browser initiation.
// It creates no account or authenticated session; copies cannot renew custody.
func (f *PasskeyService) IssueSignupFlow(ctx context.Context, p session.PreparedPreAuthIssuance) (session.PreAuthIssueResult, error) {
	w, done, owner, err := f.enterSignup(ctx)
	if err != nil {
		return session.PreAuthIssueResult{}, err
	}
	defer done()
	return owner.IssueFlow(w, p)
}

// SignupOptions prepares genuine resident registration without creating an
// account. Retain the original cookie/flow and distinct completion command.
func (f *PasskeyService) SignupOptions(ctx context.Context, r passkey.SignupRequest) (webauthn.RegistrationOptions, error) {
	w, done, owner, err := f.enterSignup(ctx)
	if err != nil {
		return webauthn.RegistrationOptions{}, err
	}
	defer done()
	return owner.RegistrationOptions(w, r)
}

// KeyedSignupOptions preserves the actual native request-key mapping. Only a
// freshly committed winner reveals options; matching retries are metadata-only.
func (f *PasskeyService) KeyedSignupOptions(ctx context.Context, r passkey.KeyedSignupOptionsRequest) (passkey.KeyedRegistrationOptionsResult, error) {
	w, done, owner, err := f.enterSignup(ctx)
	if err != nil {
		return passkey.KeyedRegistrationOptionsResult{}, err
	}
	defer done()
	return owner.KeyedRegistrationOptions(w, r)
}

// SignupRateSource reads genuine original-flow/create-ceremony rate metadata
// through current graph admission. It authenticates no user and creates,
// consumes or renews no authority. Signup independently revalidates and commits.
func (f *PasskeyService) SignupRateSource(ctx context.Context, r passkey.SignupCeremonyRateRequest) (passkey.CeremonyRateSource, error) {
	w, done, owner, err := f.enterSignup(ctx)
	if err != nil {
		return passkey.CeremonyRateSource{}, err
	}
	defer done()
	return owner.SignupRateSource(w, r)
}

// Signup verifies the actual authenticator response and atomically creates the
// account, credential, initial authorities, session and required lifecycle events.
// Only fresh acknowledged commitment permits bearer/CSRF delivery.
func (f *PasskeyService) Signup(ctx context.Context, r passkey.SignupCompletion) (passkey.SignupResult, error) {
	w, done, owner, err := f.enterSignup(ctx)
	if err != nil {
		return passkey.SignupResult{}, err
	}
	defer done()
	return owner.Signup(w, r)
}

// RecoverSignupOptions returns original durability metadata under original
// browser-cookie custody and current query policy, never another challenge.
func (f *PasskeyService) RecoverSignupOptions(ctx context.Context, r passkey.SignupRequest, caller authorization.DecisionContext) (identity.CommandResult, error) {
	w, done, owner, err := f.enterSignup(ctx)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return owner.RecoverRegistrationOptions(w, r, caller)
}

// RecoverSignup reconciles the original completion without reexecuting it or
// disclosing credentials. Consumed/expired flow possession is historical only.
func (f *PasskeyService) RecoverSignup(ctx context.Context, r passkey.SignupRequest, ceremony string, caller authorization.DecisionContext) (identity.CommandResult, error) {
	w, done, owner, err := f.enterSignup(ctx)
	if err != nil {
		return identity.CommandResult{}, err
	}
	defer done()
	return owner.RecoverSignup(w, r, ceremony, caller)
}
