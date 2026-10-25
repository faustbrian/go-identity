package reference

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// PasskeySessionEnrollmentConfiguration selects genuine current-session UV for
// adding a resident key, without password proofs. Transport must be exactly
// bearer or cookie; the graph supplies original synchronizer keys for cookies.
// KeyedOptions is required for original A/B custody. Native selection enables no
// HTTP, rename, deletion or fallback. Borrowed runtime resources remain graph-owned.
type PasskeySessionEnrollmentConfiguration struct {
	Transport session.CredentialKind
	// TOTP requires the selected native passkey/TOTP owner and admits only
	// completed passkey/TOTP sessions. False preserves known-empty admission.
	TOTP bool
}

// Format redacts deployment selection.
func (PasskeySessionEnrollmentConfiguration) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("reference.PasskeySessionEnrollmentConfiguration(redacted)"))
}

// MarshalJSON rejects implicit deployment export.
func (PasskeySessionEnrollmentConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit deployment export.
func (PasskeySessionEnrollmentConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// PasskeySessionEnrollmentService is a guarded view of the graph's selected
// native additional-enrollment owner. It owns no resources or proof. Calls retain
// initialized fixed-tenant graph lifetime and the earlier caller/native deadlines.
// Actual session, self-user intent, CSRF, genuine UV, original expiry, transaction
// and retry authority remain native-owned. Retained handles deny after Close.
type PasskeySessionEnrollmentService struct{ state *storeState }

// Format excludes graph and native-owner custody.
func (PasskeySessionEnrollmentService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("reference.PasskeySessionEnrollmentService(redacted)"))
}

// MarshalJSON rejects implicit graph export.
func (PasskeySessionEnrollmentService) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit graph export.
func (PasskeySessionEnrollmentService) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SessionEnrollment returns the explicitly selected native enrollment profile.
// A handle may be obtained before initialization, but cannot execute until startup
// succeeds. Nil/unselected/closed graphs deny without IO; no HTTP is selected.
func (f *PasskeyService) SessionEnrollment() (*PasskeySessionEnrollmentService, error) {
	if f == nil || f.state == nil {
		return nil, identity.UnavailableError{}
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passkey == nil || s.features.passkey.sessionEnrollment == nil {
		return nil, identity.UnavailableError{}
	}
	return &PasskeySessionEnrollmentService{state: s}, nil
}

// EnrollmentAssertionOptions delegates A's original-key options to the native
// owner. Only fresh committed output reveals a challenge; retries are metadata.
func (f *PasskeySessionEnrollmentService) EnrollmentAssertionOptions(ctx context.Context, r passkey.SessionEnrollmentOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	if f == nil {
		return passkey.KeyedAssertionOptionsResult{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.KeyedAssertionOptionsResult{}, err
	}
	defer done()
	owner := f.state.features.passkey.sessionEnrollment
	if owner == nil {
		return passkey.KeyedAssertionOptionsResult{}, identity.UnavailableError{}
	}
	return owner.EnrollmentAssertionOptions(w, r)
}

// RegistrationOptions delegates B's genuine assertion and distinct original key.
// Native consumption and registration creation commit together, issuing no
// reusable proof or session. Preserve original intent and metadata-only retries.
func (f *PasskeySessionEnrollmentService) RegistrationOptions(ctx context.Context, r passkey.SessionEnrollmentAuthorization) (passkey.KeyedRegistrationOptionsResult, error) {
	if f == nil {
		return passkey.KeyedRegistrationOptionsResult{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.KeyedRegistrationOptionsResult{}, err
	}
	defer done()
	owner := f.state.features.passkey.sessionEnrollment
	if owner == nil {
		return passkey.KeyedRegistrationOptionsResult{}, identity.UnavailableError{}
	}
	return owner.RegistrationOptions(w, r)
}

// RegistrationOptionsForDelivery delegates the same B operation and returns the
// native owner's original A delivery ceiling alongside fresh options. Buffered
// transports check it after hooks with actual session/request/B validity; it is
// not proof or a refreshed lease. Replay/error returns zero expiry/no options.
func (f *PasskeySessionEnrollmentService) RegistrationOptionsForDelivery(ctx context.Context, r passkey.SessionEnrollmentAuthorization) (passkey.KeyedRegistrationOptionsResult, time.Time, error) {
	if f == nil {
		return passkey.KeyedRegistrationOptionsResult{}, time.Time{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.KeyedRegistrationOptionsResult{}, time.Time{}, err
	}
	defer done()
	owner := f.state.features.passkey.sessionEnrollment
	if owner == nil {
		return passkey.KeyedRegistrationOptionsResult{}, time.Time{}, identity.UnavailableError{}
	}
	return owner.RegistrationOptionsForDelivery(w, r)
}

// Register delegates C's genuine registration and original command ID, without
// an idempotency key or replacement session. The native owner atomically creates
// protocol/kernel/mapping/lifecycle effects and recovers only original metadata.
func (f *PasskeySessionEnrollmentService) Register(ctx context.Context, r passkey.SessionEnrollmentCompletion) (passkey.SessionEnrollmentResult, error) {
	if f == nil {
		return passkey.SessionEnrollmentResult{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.SessionEnrollmentResult{}, err
	}
	defer done()
	owner := f.state.features.passkey.sessionEnrollment
	if owner == nil {
		return passkey.SessionEnrollmentResult{}, identity.UnavailableError{}
	}
	return owner.Register(w, r)
}

// SessionRegistrationRateSource authenticates original native completion custody
// before challenge-rate admission. It returns metadata, not a validity lease or
// permission to consume. It creates/renews nothing and retains graph lifetime.
func (f *PasskeySessionEnrollmentService) SessionRegistrationRateSource(ctx context.Context, r passkey.SessionEnrollmentRequest, ceremonyID string) (passkey.CeremonyRateSource, error) {
	if f == nil {
		return passkey.CeremonyRateSource{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.CeremonyRateSource{}, err
	}
	defer done()
	owner := f.state.features.passkey.sessionEnrollment
	if owner == nil {
		return passkey.CeremonyRateSource{}, identity.UnavailableError{}
	}
	return owner.SessionRegistrationRateSource(w, r, ceremonyID)
}
