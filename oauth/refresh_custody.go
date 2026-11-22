package oauth

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
)

// RefreshToken owns a temporary copy of a previously stored grant secret and its
// original immutable profile/scopes. Copies share destruction and concurrent-use
// exclusion, not durable admission, token-generation locking or retry authority.
// The native owner must admit the current grant generation before constructing
// custody and destroy it on every exit. Go cannot erase runtime/compiler copies.
type RefreshToken struct {
	owner   func() *refreshTokenOwner
	profile ProviderProfile
	scopes  []string
}

type refreshTokenOwner struct {
	mu    sync.Mutex
	value []byte
	busy  bool
}

// NewRefreshToken copies the decrypted refresh secret, original persisted
// ordinary OAuth2 profile and actual granted scopes. The scopes must be a
// nonempty bounded subset of that profile, never a caller's requested upgrade.
// This validates shape only; it does not authenticate storage or authorize use.
// The caller owns clearing its source bytes. Zero/destroyed custody is invalid.
func NewRefreshToken(value []byte, storedProfile ProviderProfile, grantedScopes []string) (RefreshToken, error) {
	if storedProfile.ValidateOAuth2Callback() != nil || !visible(string(value), 1, storedProfile.MaxTokenBytes) || !validScopes(grantedScopes) {
		return RefreshToken{}, failure(InvalidInput, nil)
	}
	for _, scope := range grantedScopes {
		if !slices.Contains(storedProfile.Scopes, scope) {
			return RefreshToken{}, failure(InvalidInput, nil)
		}
	}
	owner := &refreshTokenOwner{value: bytes.Clone(value)}
	return RefreshToken{owner: func() *refreshTokenOwner { return owner }, profile: queryProfileSnapshot(storedProfile), scopes: slices.Clone(grantedScopes)}, nil
}

// Destroy terminally clears retained secret bytes across copies. An admitted
// request may finish on its private cleared-on-return copy; Destroy does not
// wait for I/O. It is idempotent and safe during Refresh.
func (t RefreshToken) Destroy() {
	if t.owner == nil {
		return
	}
	owner := t.owner()
	owner.mu.Lock()
	clear(owner.value)
	owner.value = nil
	owner.mu.Unlock()
}

func (t RefreshToken) use(ctx context.Context, fn func([]byte) error) error {
	if t.owner == nil {
		return failure(InvalidInput, ctx)
	}
	owner := t.owner()
	owner.mu.Lock()
	if owner.busy || len(owner.value) == 0 {
		owner.mu.Unlock()
		return failure(InvalidInput, ctx)
	}
	owner.busy = true
	value := bytes.Clone(owner.value)
	owner.mu.Unlock()
	defer func() {
		clear(value)
		owner.mu.Lock()
		owner.busy = false
		owner.mu.Unlock()
	}()
	return fn(value)
}

// Format redacts the retained secret and profile diagnostics.
func (RefreshToken) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.RefreshToken(redacted)"))
}

// MarshalJSON refuses accidental plaintext persistence.
func (RefreshToken) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental persistence, including map keys.
func (RefreshToken) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
