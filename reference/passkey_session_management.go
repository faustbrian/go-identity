package reference

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// PasskeySessionManagementConfiguration selects native action-bound UV label
// rename under a current passkey session. Transport must be exactly bearer or
// cookie; the graph supplies original CSRF keys for cookies. KeyedOptions is
// required. This selects neither a password proof nor HTTP, deletion, recovery
// or enrollment. TOTP explicitly selects completed passkey/TOTP sessions and
// requires Passkey.TOTP; false retains the ordinary known-empty profile. The
// sole existing graph owns all native stores and policies.
type PasskeySessionManagementConfiguration struct {
	Transport session.CredentialKind
	TOTP      bool
}

// Format redacts selected runtime configuration.
func (PasskeySessionManagementConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasskeySessionManagementConfiguration(redacted)"))
}

// MarshalJSON rejects implicit deployment configuration export.
func (PasskeySessionManagementConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit deployment configuration export.
func (PasskeySessionManagementConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// PasskeySessionManagementService is a guarded view of the graph's selected
// native session-assertion rename owner. It owns no resources and grants no
// authority. Calls require graph initialization, the fixed tenant's actual
// current session and original intent; retained handles deny after Close.
// It implements the native UpdateOptions/Update contract without bypassing
// the graph's bounded lifetime or exposing a raw adapter handle.
type PasskeySessionManagementService struct{ state *storeState }

// Format redacts graph and native owner custody.
func (PasskeySessionManagementService) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasskeySessionManagementService(redacted)"))
}

// MarshalJSON rejects implicit graph export.
func (PasskeySessionManagementService) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit graph export.
func (PasskeySessionManagementService) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SessionManagement returns the explicitly selected session-assertion profile.
// Nil selection and closed graphs deny without IO. Like Passkeys, a handle may
// be retained before initialization; it cannot execute until startup succeeds.
// The existing PasskeyService.Update remains password-proof management.
func (f *PasskeyService) SessionManagement() (*PasskeySessionManagementService, error) {
	if f == nil || f.state == nil {
		return nil, identity.UnavailableError{}
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passkey == nil || s.features.passkey.sessionManagement == nil {
		return nil, identity.UnavailableError{}
	}
	return &PasskeySessionManagementService{state: s}, nil
}

// UpdateOptions delegates original-key admission and fresh UV options to the
// native owner. Matching retries return metadata only, never another challenge.
// Calls are bounded by the earlier caller, graph and native operation budgets.
func (f *PasskeySessionManagementService) UpdateOptions(ctx context.Context, r passkey.SessionUpdateOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	if f == nil {
		return passkey.KeyedAssertionOptionsResult{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.KeyedAssertionOptionsResult{}, err
	}
	defer done()
	owner := f.state.features.passkey.sessionManagement
	if owner == nil {
		return passkey.KeyedAssertionOptionsResult{}, identity.UnavailableError{}
	}
	return owner.UpdateOptions(w, r)
}

// Update delegates genuine assertion verification and atomic rename to the
// native owner. It issues no session or reusable proof. Retain the original
// body/key for metadata-only retry and uncertain-outcome reconciliation.
func (f *PasskeySessionManagementService) Update(ctx context.Context, r passkey.SessionUpdateCompletion) (passkey.UpdateResult, error) {
	if f == nil {
		return passkey.UpdateResult{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.UpdateResult{}, err
	}
	defer done()
	owner := f.state.features.passkey.sessionManagement
	if owner == nil {
		return passkey.UpdateResult{}, identity.UnavailableError{}
	}
	return owner.Update(w, r)
}
