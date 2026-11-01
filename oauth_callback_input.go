package identity

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
)

// ErrInvalidOAuthCallbackInput identifies absent, destroyed, busy or invalid
// callback custody. It never includes authorization code, state or callback data.
var ErrInvalidOAuthCallbackInput = errors.New("identity: invalid OAuth callback input")

// OAuthCallbackLimits is a trusted provider profile, not callback-selected
// policy. MaxCodeBytes must be 1..1 MiB and StateBytes 32..64. The code ceiling
// bounds ephemeral copies; providers should select a smaller documented bound.
// StateBytes selects this platform's random-state profile, not OAuth's general
// state syntax. Construction neither verifies the state nor admits exchange.
type OAuthCallbackLimits struct {
	MaxCodeBytes int
	StateBytes   int
}

// OAuthCallbackInput owns one original authorization code and raw RP state.
// Value copies share terminal destruction. Its zero value is invalid. Only Use
// exposes bounded temporary copies, never a persistence or authority projection.
// Destroy is required after bounded use; Go cannot guarantee runtime-wide erasure.
type OAuthCallbackInput struct{ owner func() *oauthCallbackOwner }

// mu owns code, state and busy. No caller callback runs while mu is held.
type oauthCallbackOwner struct {
	mu    sync.Mutex
	code  []byte
	state []byte
	busy  bool
}

// NewOAuthCallbackInput copies a nonempty RFC 6749 Appendix A.11 authorization
// code without trimming or normalization, and canonical unpadded base64url RP
// state of the configured decoded size. Appendix A permits spaces and +/=:
// in codes; OTP and bearer grammars must not be substituted here. Input is not
// retained. Invalid input returns no custody and ErrInvalidOAuthCallbackInput.
func NewOAuthCallbackInput(code []byte, state string, limits OAuthCallbackLimits) (OAuthCallbackInput, error) {
	if limits.MaxCodeBytes <= 0 || limits.MaxCodeBytes > 1<<20 || limits.StateBytes < 32 || limits.StateBytes > 64 || len(code) == 0 || len(code) > limits.MaxCodeBytes || len(state) != base64.RawURLEncoding.EncodedLen(limits.StateBytes) {
		return OAuthCallbackInput{}, ErrInvalidOAuthCallbackInput
	}
	for _, value := range code {
		if value < 0x20 || value > 0x7e {
			return OAuthCallbackInput{}, ErrInvalidOAuthCallbackInput
		}
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(state)
	defer clear(raw)
	if err != nil || len(raw) != limits.StateBytes || base64.RawURLEncoding.EncodeToString(raw) != state {
		return OAuthCallbackInput{}, ErrInvalidOAuthCallbackInput
	}
	owner := &oauthCallbackOwner{code: bytes.Clone(code), state: []byte(state)}
	return OAuthCallbackInput{owner: func() *oauthCallbackOwner { return owner }}, nil
}

func (input OAuthCallbackInput) live() bool {
	if input.owner == nil {
		return false
	}
	owner := input.owner()
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return len(owner.code) > 0 && !owner.busy
}

// Destroy terminally clears this owner's retained bytes across all value copies.
// It is idempotent, race-safe and callable during Use. An admitted callback may
// finish on its private borrow, which is cleared on return; Destroy never waits.
func (input OAuthCallbackInput) Destroy() {
	if input.owner == nil {
		return
	}
	owner := input.owner()
	owner.mu.Lock()
	clear(owner.code)
	clear(owner.state)
	owner.code, owner.state = nil, nil
	owner.mu.Unlock()
}

// Use admits one synchronous callback across all aliases. Nil/cancelled context,
// nil callback, zero/destroyed custody, or concurrent/reentrant use denies before
// invocation. The callback receives exact private mutable copies and must obey
// ctx, retain neither slice nor copies, and perform no asynchronous access.
// Copies are cleared on every exit. Panics are suppressed without their values;
// callback errors retain errors.Is/As classification behind redacted diagnostics.
// No goroutines are started and callbacks never execute under the owner lock.
func (input OAuthCallbackInput) Use(ctx context.Context, callback func(context.Context, []byte, []byte) error) (err error) {
	if ctx == nil || callback == nil || input.owner == nil {
		return ErrInvalidOAuthCallbackInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	owner := input.owner()
	owner.mu.Lock()
	if len(owner.code) == 0 || owner.busy {
		owner.mu.Unlock()
		return ErrInvalidOAuthCallbackInput
	}
	owner.busy = true
	// Exact capacities prevent legal callback reslicing from creating data
	// beyond the lengths that this owner can clear on callback exit.
	code, state := make([]byte, len(owner.code)), make([]byte, len(owner.state))
	copy(code, owner.code)
	copy(state, owner.state)
	owner.mu.Unlock()
	completed := false
	defer func() {
		clear(code)
		clear(state)
		owner.mu.Lock()
		owner.busy = false
		owner.mu.Unlock()
		if !completed {
			_ = recover()
			err = ErrInvalidOAuthCallbackInput
		}
	}()
	cause := callback(ctx, code, state)
	completed = true
	if cause != nil {
		return oauthCallbackCause(func() error { return cause })
	}
	return nil
}

type oauthCallbackCause func() error

func (oauthCallbackCause) Error() string       { return "identity: OAuth callback input use failed" }
func (cause oauthCallbackCause) Unwrap() error { return cause() }

// Format redacts all diagnostic verbs, including unsupported verbs.
func (OAuthCallbackInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("identity.OAuthCallbackInput(redacted)"))
}

// MarshalJSON refuses accidental transport or persistence of callback custody.
func (OAuthCallbackInput) MarshalJSON() ([]byte, error) { return nil, ErrInvalidOAuthCallbackInput }

// MarshalText refuses accidental text or map-key export of callback custody.
func (OAuthCallbackInput) MarshalText() ([]byte, error) { return nil, ErrInvalidOAuthCallbackInput }
