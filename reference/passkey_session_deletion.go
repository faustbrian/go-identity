package reference

import (
	"context"
	"fmt"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	passkey "github.com/faustbrian/go-passkey"
)

// PasskeySessionDeletionConfiguration selects genuine current-session UV removal
// while an independently usable resident key in the selected algorithm profile
// remains. Transport must be
// bearer or cookie; the graph injects original CSRF keys for cookies. KeyedOptions
// is required. Selection enables no HTTP or password/OTP recovery fallback.
type PasskeySessionDeletionConfiguration struct{ Transport session.CredentialKind }

// Format redacts deployment selection.
func (PasskeySessionDeletionConfiguration) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("reference.PasskeySessionDeletionConfiguration(redacted)"))
}

// MarshalJSON rejects implicit deployment export.
func (PasskeySessionDeletionConfiguration) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit deployment export.
func (PasskeySessionDeletionConfiguration) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// PasskeySessionDeletionService borrows the graph's selected native removal
// owner without exposing its stores or bypassing initialized graph lifetime.
// Calls preserve actual current-session/policy/CSRF, original-key/intent/expiry,
// genuine UV, transaction and recovery authority. Retained handles deny after
// Close. It owns no resource, proof, goroutine or automatic retry.
type PasskeySessionDeletionService struct{ state *storeState }

// Format excludes graph and native-owner custody.
func (PasskeySessionDeletionService) Format(f fmt.State, _ rune) {
	_, _ = f.Write([]byte("reference.PasskeySessionDeletionService(redacted)"))
}

// MarshalJSON rejects implicit graph export.
func (PasskeySessionDeletionService) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects implicit graph export.
func (PasskeySessionDeletionService) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// SessionDeletion returns only the explicitly selected native removal profile.
// A pre-initialization handle cannot execute; nil/unselected/closed graphs deny
// without IO. Existing password-proof Deletion remains a separate selection.
func (f *PasskeyService) SessionDeletion() (*PasskeySessionDeletionService, error) {
	if f == nil || f.state == nil {
		return nil, identity.UnavailableError{}
	}
	s := f.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.passkey == nil || s.features.passkey.sessionDeletion == nil {
		return nil, identity.UnavailableError{}
	}
	return &PasskeySessionDeletionService{state: s}, nil
}

// DeleteOptions delegates original-key admission and genuine action-bound UV
// options. Retries return metadata, never another challenge or renewed lease.
func (f *PasskeySessionDeletionService) DeleteOptions(ctx context.Context, r passkey.SessionDeleteOptionsRequest) (passkey.KeyedAssertionOptionsResult, error) {
	if f == nil {
		return passkey.KeyedAssertionOptionsResult{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.KeyedAssertionOptionsResult{}, err
	}
	defer done()
	return f.state.features.passkey.sessionDeletion.DeleteOptions(w, r)
}

// Delete delegates genuine UV consumption, exact key removal and affected
// session invalidation to the sole native Work. Success acknowledges only the
// original invocation; it cannot make its deliberately invalidated session usable.
func (f *PasskeySessionDeletionService) Delete(ctx context.Context, r passkey.SessionDeleteCompletion) (passkey.SessionDeleteResult, error) {
	if f == nil {
		return passkey.SessionDeleteResult{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.SessionDeleteResult{}, err
	}
	defer done()
	return f.state.features.passkey.sessionDeletion.Delete(w, r)
}

// RecoverDelete delegates original command/target durability lookup under a
// currently valid same-user passkey session and delete policy. After removal,
// sign in with the surviving key. Recovery repeats no mutation or assertion,
// returns no credential and never renews original authority or options.
func (f *PasskeySessionDeletionService) RecoverDelete(ctx context.Context, r passkey.SessionDeleteRequest, q identity.RecoveryQuery) (passkey.SessionDeleteResult, error) {
	if f == nil {
		return passkey.SessionDeleteResult{}, identity.UnavailableError{}
	}
	w, done, err := (&PasskeyService{state: f.state}).enterFixed(ctx)
	if err != nil {
		return passkey.SessionDeleteResult{}, err
	}
	defer done()
	return f.state.features.passkey.sessionDeletion.RecoverDelete(w, r, q)
}
