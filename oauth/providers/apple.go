// Package providers supplies explicit built-in OAuth profiles and provider-specific
// operations. Google composes the existing OAuth owner; Apple signs client-secret
// JWTs with preprovisioned encrypted P-256 keys, not Apple authentication.
package providers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	secretenvelope "github.com/faustbrian/go-secret-envelope/v2"
)

// AppleClientSecretMaxLifetime is Apple's 15,777,000-second maximum. The
// minimum is one second and fractional seconds are never rounded or truncated.
const AppleClientSecretMaxLifetime = 15777000 * time.Second

const appleOperation = "identity.oauth.provider-apple-client-secret-sign"

// AppleClientSecretError classifies signing failure without retaining an
// underlying error, key identifier, plaintext or collaborator panic value.
// Code is exactly invalid_bounds, canceled or signer_failure.
type AppleClientSecretError struct{ code string }

// Error returns the stable classification only.
func (e AppleClientSecretError) Error() string { return e.code }

// Code returns the stable signing classification, never provider diagnostics.
func (e AppleClientSecretError) Code() string { return e.code }

// AppleClientSecretUseError is the sole result of a nil/invalid secret,
// overlapping or nil callback, callback error or recovered callback panic.
// It never wraps callback diagnostics, which may contain the JWT.
type AppleClientSecretUseError struct{}

// Error returns a fixed safe message.
func (AppleClientSecretUseError) Error() string { return "apple_client_secret_use" }

// AppleSigningKeyHandle names a preprovisioned key without accepting key bytes
// or an envelope. Its zero value is invalid. Copies preserve exact identity,
// including case, but diagnostics and implicit serialization never reveal it.
type AppleSigningKeyHandle struct{ id string }

// NewAppleSigningKeyHandle accepts 1..256 ASCII bytes in [A-Za-z0-9._:/-]+,
// byte-for-byte, without trimming or normalization. It performs no lookup and
// grants no signing authorization. Invalid input returns zero/invalid_bounds.
func NewAppleSigningKeyHandle(identifier string) (AppleSigningKeyHandle, error) {
	if len(identifier) < 1 || len(identifier) > 256 {
		return AppleSigningKeyHandle{}, AppleClientSecretError{"invalid_bounds"}
	}
	for i := range len(identifier) {
		b := identifier[i]
		if !asciiAlphanumeric(b) && b != '.' && b != '_' && b != ':' && b != '/' && b != '-' {
			return AppleSigningKeyHandle{}, AppleClientSecretError{"invalid_bounds"}
		}
	}
	return AppleSigningKeyHandle{id: identifier}, nil
}

// Format redacts even nested diagnostic formatting.
func (AppleSigningKeyHandle) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON rejects implicit handle disclosure.
func (AppleSigningKeyHandle) MarshalJSON() ([]byte, error) {
	return nil, AppleClientSecretUseError{}
}

// MarshalText rejects implicit handle disclosure, including map keys.
func (AppleSigningKeyHandle) MarshalText() ([]byte, error) {
	return nil, AppleClientSecretUseError{}
}

// AppleSigningKeyContext returns the exact envelope AAD for one key handle and
// this signing purpose. Use it during trusted PKCS8-DER key provisioning and
// retain the same handle. Context is authenticated nonsecret configuration;
// this function neither encrypts material nor grants signing permission.
func AppleSigningKeyContext(handle AppleSigningKeyHandle) (secretenvelope.Context, error) {
	if handle.id == "" {
		return secretenvelope.Context{}, AppleClientSecretError{"invalid_bounds"}
	}
	// Context exposes AAD to providers and diagnostics. Bind the exact handle
	// without turning that public projection into an opaque-handle unwrap path.
	digest := sha256.Sum256([]byte(appleOperation + "\x00key-handle-v1\x00" + handle.id))
	return secretenvelope.NewContext(map[string]string{
		"operation": appleOperation,
		"version":   "1",
		"key":       hex.EncodeToString(digest[:]),
	})
}

// AppleSigningKeyEnvelope binds one opaque handle to a preprovisioned
// secret-envelope payload. Plaintext must be PKCS8 DER for an ECDSA P-256 key,
// encrypted with AppleSigningKeyContext. No raw private key is accepted here.
type AppleSigningKeyEnvelope struct {
	Handle   AppleSigningKeyHandle
	Envelope secretenvelope.Envelope
}

// Format redacts handle and encrypted material in enclosing diagnostics.
func (AppleSigningKeyEnvelope) Format(s fmt.State, _ rune) { redact(s) }

// AppleSigningClock supplies original signing time once per valid request.
// It must return promptly and be safe for concurrent use. Zero and fractional
// seconds are rejected; successful metadata is represented in UTC.
type AppleSigningClock interface{ Now() time.Time }

// AppleClientSecretSignerConfig selects immutable encrypted keys and explicit
// trusted dependencies. Envelope and Clock remain caller-owned/concurrent-safe.
// Keys are copied at construction; 1..64 unique handles are allowed. Timeout
// defaults to ten seconds; explicit bounds are 1ms..30s and never extend ctx.
type AppleClientSecretSignerConfig struct {
	Envelope *secretenvelope.Service
	Keys     []AppleSigningKeyEnvelope
	Clock    AppleSigningClock
	Timeout  time.Duration
}

// Format prevents configuration from exposing key handles or collaborator data.
func (AppleClientSecretSignerConfig) Format(s fmt.State, _ rune) { redact(s) }

// AppleClientSecretSigner resolves only its immutable preprovisioned key set,
// decrypts through the existing envelope owner and signs only this operation.
// It owns no provider, goroutine, persistent state or shutdown resource. Calls
// may run concurrently with distinct results; borrowed dependencies must remain
// alive and honor bounded contexts. Local crypto and Clock cannot be preempted.
type AppleClientSecretSigner struct {
	envelope *secretenvelope.Service
	keys     map[AppleSigningKeyHandle]secretenvelope.Envelope
	clock    AppleSigningClock
	timeout  time.Duration
}

// NewAppleClientSecretSigner validates/copies configuration without lookup,
// decryption, clock reads or other external operations. Missing dependencies,
// invalid/duplicate keys and bounds return nil/invalid_bounds. Decryption,
// PKCS8/curve and wrapping-key failures are classified by Sign instead.
func NewAppleClientSecretSigner(c AppleClientSecretSignerConfig) (*AppleClientSecretSigner, error) {
	if c.Timeout == 0 {
		c.Timeout = 10 * time.Second
	}
	if c.Envelope == nil || c.Clock == nil || len(c.Keys) < 1 || len(c.Keys) > 64 || c.Timeout < time.Millisecond || c.Timeout > 30*time.Second {
		return nil, AppleClientSecretError{"invalid_bounds"}
	}
	keys := make(map[AppleSigningKeyHandle]secretenvelope.Envelope, len(c.Keys))
	for _, key := range c.Keys {
		_, duplicate := keys[key.Handle]
		ciphertext := key.Envelope.Ciphertext()
		validSize := len(ciphertext) > 16 && len(ciphertext) <= 4096+16
		clear(ciphertext)
		if key.Handle.id == "" || duplicate || !validSize {
			return nil, AppleClientSecretError{"invalid_bounds"}
		}
		keys[key.Handle] = key.Envelope
	}
	return &AppleClientSecretSigner{envelope: c.Envelope, keys: keys, clock: c.Clock, timeout: c.Timeout}, nil
}

// Format redacts signer internals and collaborators.
func (*AppleClientSecretSigner) Format(s fmt.State, _ rune) { redact(s) }

// AppleClientSecretRequest is exactly the selected Apple signing intent.
// TeamID/KeyID are ten uppercase ASCII alphanumerics. ClientID preserves the
// case-sensitive App/Services ID, 1..255 ASCII alphanumerics, periods or hyphens.
// Lifetime is an integral 1..15,777,000 seconds. The caller authorizes use of
// these configured identities; signing does not prove Apple registration.
type AppleClientSecretRequest struct {
	TeamID, ClientID, KeyID string
	SigningKey              AppleSigningKeyHandle
	Lifetime                time.Duration
}

// Format redacts complete signing intent and its key handle.
func (AppleClientSecretRequest) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON rejects implicit signing-intent disclosure.
func (AppleClientSecretRequest) MarshalJSON() ([]byte, error) {
	return nil, AppleClientSecretUseError{}
}

// MarshalText rejects implicit signing-intent disclosure.
func (AppleClientSecretRequest) MarshalText() ([]byte, error) {
	return nil, AppleClientSecretUseError{}
}

// AppleClientSecretResult contains callback-only JWT custody and original
// UTC metadata. Its zero value has no usable secret. Destroy Secret when done;
// never use it at/after ExpiresAt. This is neither a session nor provider proof.
type AppleClientSecretResult struct {
	Secret              AppleClientSecret
	IssuedAt, ExpiresAt time.Time
}

// Format redacts the result and never formats JWT custody.
func (AppleClientSecretResult) Format(s fmt.State, _ rune) { redact(s) }

// Sign produces the exact ES256 Apple client secret with ordered alg/kid and
// iss/iat/exp/aud/sub, no typ or extra fields, and an unpadded 64-byte JOSE
// P-256 signature. It reads the injected clock once, checks expiry arithmetic,
// and never retries a key operation. Every failure returns a zero result and
// only invalid_bounds, canceled or signer_failure. Collaborator panics and
// error diagnostics are discarded. Owned DER and JWT temporaries are cleared
// best-effort; Go/crypto copies cannot promise complete memory erasure.
func (s *AppleClientSecretSigner) Sign(ctx context.Context, r AppleClientSecretRequest) (result AppleClientSecretResult, err error) {
	if ctx == nil || !validAppleID(r.TeamID) || !validAppleID(r.KeyID) || !validAppleClientID(r.ClientID) || r.SigningKey.id == "" || r.Lifetime < time.Second || r.Lifetime > AppleClientSecretMaxLifetime || r.Lifetime%time.Second != 0 {
		return result, AppleClientSecretError{"invalid_bounds"}
	}
	if ctx.Err() != nil {
		return result, AppleClientSecretError{"canceled"}
	}
	if s == nil || s.envelope == nil || s.clock == nil || s.timeout <= 0 {
		return result, AppleClientSecretError{"signer_failure"}
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			result.Secret.Destroy()
			result = AppleClientSecretResult{}
			err = appleFailure(ctx)
		}
	}()
	now := s.clock.Now()
	seconds := now.Unix()
	lifetime := int64(r.Lifetime / time.Second)
	if now.IsZero() || now.Nanosecond() != 0 || !time.Unix(seconds, 0).Equal(now) || seconds > math.MaxInt64-lifetime {
		return result, AppleClientSecretError{"invalid_bounds"}
	}
	// time.Time counts internal seconds from year 1. A fitting Unix sum can
	// still overflow that representation; prove exact forward metadata before
	// using a key, without imposing an arbitrary calendar-year restriction.
	expiresAt := time.Unix(seconds+lifetime, 0).UTC()
	if !expiresAt.After(now) || expiresAt.Sub(now) != r.Lifetime {
		return result, AppleClientSecretError{"invalid_bounds"}
	}
	if ctx.Err() != nil {
		return result, AppleClientSecretError{"canceled"}
	}
	encrypted, ok := s.keys[r.SigningKey]
	if !ok {
		return result, AppleClientSecretError{"signer_failure"}
	}
	binding, _ := AppleSigningKeyContext(r.SigningKey)
	der, err := s.envelope.Decrypt(ctx, secretenvelope.DecryptRequest{Envelope: encrypted, Context: binding})
	defer clear(der)
	if err != nil || ctx.Err() != nil || len(der) == 0 || len(der) > 4096 {
		return AppleClientSecretResult{}, appleFailure(ctx)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return AppleClientSecretResult{}, appleFailure(ctx)
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return AppleClientSecretResult{}, appleFailure(ctx)
	}
	defer clear(private.D.Bits())
	if private.Curve != elliptic.P256() {
		return AppleClientSecretResult{}, appleFailure(ctx)
	}

	// Apple's shared Creating a client secret article fixes these fields and
	// ES256/P-256; the retained provider goal additionally fixes member order.
	// See docs/protocol-sources.md for the attributable official source pin.
	header, _ := json.Marshal(struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}{"ES256", r.KeyID})
	defer clear(header)
	claims, _ := json.Marshal(struct {
		Issuer   string `json:"iss"`
		IssuedAt int64  `json:"iat"`
		Expiry   int64  `json:"exp"`
		Audience string `json:"aud"`
		Subject  string `json:"sub"`
	}{r.TeamID, seconds, seconds + lifetime, "https://appleid.apple.com", r.ClientID})
	defer clear(claims)
	input := base64.RawURLEncoding.AppendEncode(nil, header)
	input = append(input, '.')
	input = base64.RawURLEncoding.AppendEncode(input, claims)
	defer func() { clear(input) }()
	digest := sha256.Sum256(input)
	if ctx.Err() != nil {
		return AppleClientSecretResult{}, appleFailure(ctx)
	}
	signatureR, signatureS, err := ecdsa.Sign(rand.Reader, private, digest[:])
	if err != nil || ctx.Err() != nil {
		return AppleClientSecretResult{}, appleFailure(ctx)
	}
	var signature [64]byte
	defer clear(signature[:])
	signatureR.FillBytes(signature[:32])
	signatureS.FillBytes(signature[32:])
	input = append(input, '.')
	input = base64.RawURLEncoding.AppendEncode(input, signature[:])
	owned := append([]byte(nil), input...)
	return AppleClientSecretResult{
		Secret:    AppleClientSecret{owner: &appleSecretOwner{jwt: owned}},
		IssuedAt:  now.UTC(),
		ExpiresAt: expiresAt,
	}, nil
}

func appleFailure(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return AppleClientSecretError{"canceled"}
	}
	return AppleClientSecretError{"signer_failure"}
}

func validAppleID(value string) bool {
	if len(value) != 10 {
		return false
	}
	for i := range len(value) {
		b := value[i]
		if (b < 'A' || b > 'Z') && (b < '0' || b > '9') {
			return false
		}
	}
	return true
}

func validAppleClientID(value string) bool {
	if len(value) < 1 || len(value) > 255 {
		return false
	}
	for i := range len(value) {
		b := value[i]
		if !asciiAlphanumeric(b) && b != '.' && b != '-' {
			return false
		}
	}
	return true
}

func asciiAlphanumeric(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

func redact(s fmt.State) { _, _ = s.Write([]byte("[REDACTED]")) }

type appleSecretOwner struct {
	mu   sync.Mutex
	jwt  []byte
	busy bool
}

// AppleClientSecret holds no exported JWT bytes. Copies share synchronized
// custody. Use serially for intended synchronous token-request encoding, then
// Destroy. Overlapping/reentrant borrows fail rather than blocking callbacks.
type AppleClientSecret struct{ owner *appleSecretOwner }

// Format redacts JWT custody even inside enclosing diagnostics.
func (AppleClientSecret) Format(s fmt.State, _ rune) { redact(s) }

// MarshalJSON rejects implicit JWT disclosure.
func (AppleClientSecret) MarshalJSON() ([]byte, error) {
	return nil, AppleClientSecretUseError{}
}

// MarshalText rejects implicit JWT disclosure.
func (AppleClientSecret) MarshalText() ([]byte, error) {
	return nil, AppleClientSecretUseError{}
}

// Use lends a private mutable JWT copy to one synchronous token-request
// encoder outside the custody lock. Do not retain, copy for later use, format,
// log or otherwise disclose it. The borrowed copy is overwritten on success,
// error and panic. Callback diagnostics are discarded, not wrapped. Destroy
// during an admitted callback cannot revoke its already borrowed private copy.
func (s AppleClientSecret) Use(encode func([]byte) error) (err error) {
	if s.owner == nil || encode == nil {
		return AppleClientSecretUseError{}
	}
	owner := s.owner
	owner.mu.Lock()
	if owner.busy || len(owner.jwt) == 0 {
		owner.mu.Unlock()
		return AppleClientSecretUseError{}
	}
	borrowed := append([]byte(nil), owner.jwt...)
	owner.busy = true
	owner.mu.Unlock()
	defer func() {
		clear(borrowed)
		owner.mu.Lock()
		owner.busy = false
		owner.mu.Unlock()
		if recover() != nil {
			err = AppleClientSecretUseError{}
		}
	}()
	if encode(borrowed) != nil {
		return AppleClientSecretUseError{}
	}
	return nil
}

// Destroy clears retained JWT bytes for every alias, idempotently. Already
// admitted private callback copies finish and clear independently. This is
// best-effort buffer clearing, not a guarantee about Go/runtime/encoder copies.
func (s AppleClientSecret) Destroy() {
	if s.owner == nil {
		return
	}
	s.owner.mu.Lock()
	clear(s.owner.jwt)
	s.owner.jwt = nil
	s.owner.mu.Unlock()
}
