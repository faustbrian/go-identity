package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
	"sync"
	"time"
)

// PKCEVerifier owns the exact RFC7636 verifier bytes. Copies share destruction;
// zero values are invalid. Construction is not state admission or proof that
// the verifier matches any reserved native transaction. Destroy after exchange.
type PKCEVerifier struct{ owner func() *verifierOwner }
type verifierOwner struct {
	mu    sync.Mutex
	value []byte
	busy  bool
}

// NewPKCEVerifier copies 43..128 unreserved ASCII bytes without normalization.
// The native callback worker constructs it only after reserving authenticated
// state and decrypting the transaction's bound verifier ciphertext.
func NewPKCEVerifier(value []byte) (PKCEVerifier, error) {
	if len(value) < 43 || len(value) > 128 {
		return PKCEVerifier{}, failure(InvalidInput, nil)
	}
	for _, b := range value {
		if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '-' && b != '.' && b != '_' && b != '~' {
			return PKCEVerifier{}, failure(InvalidInput, nil)
		}
	}
	o := &verifierOwner{value: bytes.Clone(value)}
	return PKCEVerifier{owner: func() *verifierOwner { return o }}, nil
}

// Challenge returns the S256 challenge or empty for destroyed/zero custody.
func (v PKCEVerifier) Challenge() string {
	if v.owner == nil {
		return ""
	}
	o := v.owner()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.value) == 0 {
		return ""
	}
	sum := sha256.Sum256(o.value)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Destroy terminally clears retained bytes across all copies. Existing admitted
// use owns its own cleared-on-return copy; Destroy does not wait for I/O.
func (v PKCEVerifier) Destroy() {
	if v.owner == nil {
		return
	}
	o := v.owner()
	o.mu.Lock()
	clear(o.value)
	o.value = nil
	o.mu.Unlock()
}

func (v PKCEVerifier) use(ctx context.Context, fn func([]byte) error) error {
	if v.owner == nil {
		return failure(InvalidInput, ctx)
	}
	o := v.owner()
	o.mu.Lock()
	if o.busy || len(o.value) == 0 {
		o.mu.Unlock()
		return failure(InvalidInput, ctx)
	}
	o.busy = true
	value := make([]byte, len(o.value))
	copy(value, o.value)
	o.mu.Unlock()
	defer func() { clear(value); o.mu.Lock(); o.busy = false; o.mu.Unlock() }()
	return fn(value)
}

// Format always redacts the verifier.
func (PKCEVerifier) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.PKCEVerifier(redacted)"))
}

// MarshalJSON refuses accidental persistence.
func (PKCEVerifier) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental persistence.
func (PKCEVerifier) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// TokenBytes is a bounded synchronous borrowed projection for encryption or an
// explicitly authorized token consumer, never a general claims map. The callback
// must retain neither slices nor copies, must not use them asynchronously and
// must obey context. Each capacity equals length; bytes are cleared on return.
type TokenBytes struct{ AccessToken, RefreshToken, IDToken []byte }

// Format redacts every token field even if the borrower logs the projection.
func (TokenBytes) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("oauth.TokenBytes(redacted)")) }

// MarshalJSON refuses accidental serialization; use explicit encrypted custody.
func (TokenBytes) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental serialization.
func (TokenBytes) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// TokenSet owns only validated-response tokens. Copies share destruction and a
// single borrow admission. Zero values cannot be borrowed. Destroy is required
// after encryption/use; Go cannot guarantee erasure of runtime/compiler copies.
// Metadata is immutable and remains readable after destruction.
type TokenSet struct {
	owner                 func() *tokenOwner
	receivedAt, expiresAt time.Time
	requested, granted    []string
	scopeReported         bool
}
type tokenOwner struct {
	mu                  sync.Mutex
	access, refresh, id []byte
	busy                bool
}

// RequestedScopes returns a copy of the exact configured request scope order.
func (t TokenSet) RequestedScopes() []string { return slices.Clone(t.requested) }

// GrantedScopes returns provider-reported scopes, or the RFC6749 section5.1
// equivalent requested scopes when scope was omitted. ScopeReported distinguishes
// those cases; it never silently upgrades a reported subset.
func (t TokenSet) GrantedScopes() []string { return slices.Clone(t.granted) }

// ScopeReported states whether scope was explicitly present in the response.
func (t TokenSet) ScopeReported() bool { return t.scopeReported }

// ReceivedAt is the trusted clock instant the complete response was received.
func (t TokenSet) ReceivedAt() time.Time { return t.receivedAt }

// ExpiresAt is ReceivedAt plus the provider's required bounded expires_in, not
// an ID-token or session expiry. No default expiry is invented.
func (t TokenSet) ExpiresAt() time.Time { return t.expiresAt }

// Destroy terminally clears retained tokens across all aliases, without waiting
// for admitted private borrows. It is idempotent and safe during Use.
func (t TokenSet) Destroy() {
	if t.owner == nil {
		return
	}
	o := t.owner()
	o.mu.Lock()
	clear(o.access)
	clear(o.refresh)
	clear(o.id)
	o.access, o.refresh, o.id = nil, nil, nil
	o.mu.Unlock()
}

// Use synchronously lends one exact-capacity mutable copy of each token. Nil or
// cancelled context, nil callback, zero/destroyed custody and concurrent/reentrant
// calls deny before invocation. Panics are suppressed without their values;
// callback errors preserve errors.Is/As behind redacted diagnostics. No callback
// executes under a lock and no goroutine is started.
func (t TokenSet) Use(ctx context.Context, fn func(context.Context, TokenBytes) error) (err error) {
	if ctx == nil || fn == nil || t.owner == nil {
		return failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return failure(Unavailable, ctx)
	}
	o := t.owner()
	o.mu.Lock()
	if o.busy || len(o.access) == 0 {
		o.mu.Unlock()
		return failure(InvalidInput, ctx)
	}
	o.busy = true
	clone := func(b []byte) []byte { out := make([]byte, len(b)); copy(out, b); return out }
	borrow := TokenBytes{clone(o.access), clone(o.refresh), clone(o.id)}
	o.mu.Unlock()
	completed := false
	defer func() {
		clear(borrow.AccessToken)
		clear(borrow.RefreshToken)
		clear(borrow.IDToken)
		o.mu.Lock()
		o.busy = false
		o.mu.Unlock()
		if !completed {
			_ = recover()
			err = failure(InvalidInput, ctx)
		}
	}()
	cause := fn(ctx, borrow)
	completed = true
	if cause != nil {
		return custodyCause(func() error { return cause })
	}
	return nil
}

type custodyCause func() error

func (custodyCause) Error() string   { return "oauth: token borrow failed" }
func (c custodyCause) Unwrap() error { return c() }

// Format always redacts token custody.
func (TokenSet) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("oauth.TokenSet(redacted)")) }

// MarshalJSON refuses accidental persistence; use Use to encrypt tokens.
func (TokenSet) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental persistence.
func (TokenSet) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
