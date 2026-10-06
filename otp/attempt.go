package otp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
)

var (
	// ErrInvalidAttempt rejects zero or unsupported preparation input, without
	// preserving raw codes, scope data or underlying credential errors.
	ErrInvalidAttempt = errors.New("otp: invalid attempt input")
	// ErrAttemptUnavailable means incomplete, failed or zero entropy. Its cause
	// is deliberately redacted. No command or recovery identity is produced.
	ErrAttemptUnavailable = errors.New("otp: attempt entropy unavailable")
)

// AttemptMode explicitly separates separately limited non-consuming checks
// from consuming reservations. Zero/unknown modes are invalid. The store, not
// this tag, grants any reservation after counted locked verification.
type AttemptMode uint8

const (
	// AttemptModeCheck never creates a proof or reservation on success.
	AttemptModeCheck AttemptMode = iota + 1
	// AttemptModeConsume selects the sole generation-fenced reservation on
	// committed correct-code verification and current authorization checks.
	AttemptModeConsume
)

// AttemptID is server-issued canonical base64url random128 correlation data.
// Its empty value is invalid. Parsing or conversion never grants authority;
// Prepare accepts no caller ID. Keep the same ID across retries/recovery and
// never accept it from an untrusted client as a replacement submission.
type AttemptID string

func (AttemptID) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "otp.AttemptID(redacted)") }
func (AttemptID) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AttemptID) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// AttemptFingerprint is canonical base64url HMAC-SHA-256 metadata over exact
// scope, mode, expected version, key version and submitted code. It is not an
// unkeyed digest, bearer, proof or unmetered online verification interface.
// It remains stable for recovery; callers must not select or recompute it.
type AttemptFingerprint string

func (AttemptFingerprint) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.AttemptFingerprint(redacted)")
}
func (AttemptFingerprint) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AttemptFingerprint) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// AttemptBindings is the code-free trusted adapter projection. Continuation
// contains exact declared workflow scope/authorization, not authenticated proof.
// An adapter must validate locked primary challenge state before comparison;
// the ID/fingerprint pair binds one immutable logical submission. This value
// alone cannot dispatch an attempt or authorize a protected mutation.
type AttemptBindings struct {
	AttemptID             AttemptID
	Fingerprint           AttemptFingerprint
	FingerprintKeyVersion uint32
	Continuation          Continuation
	Mode                  AttemptMode
	ExpectedVersion       uint64
}

func (AttemptBindings) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.AttemptBindings(redacted)")
}
func (AttemptBindings) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AttemptBindings) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// AttemptRecoveryIdentity contains no code, key, destination or mutable context.
// Use its exact trusted tenant/ID/fingerprint/key version to query the original
// durable outcome without re-comparison or a second denial decrement. Absence
// alone does not prove not-committed while the original transaction is live.
// This correlation data grants no mutation or authentication authority.
type AttemptRecoveryIdentity struct {
	TenantID              identity.TenantID
	AttemptID             AttemptID
	Fingerprint           AttemptFingerprint
	FingerprintKeyVersion uint32
}

func (AttemptRecoveryIdentity) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.AttemptRecoveryIdentity(redacted)")
}
func (AttemptRecoveryIdentity) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AttemptRecoveryIdentity) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// AttemptCommand is an immutable server-prepared submission. Zero is invalid.
// Copies retain the opaque submitted code; discard all copies after a terminal
// outcome, retaining only Recovery on ambiguity. It owns no IO or durable state
// and supplies no counted success, authentication proof or reservation. Never
// store this whole object: persist only code-free replay metadata and outcomes.
type AttemptCommand struct{ state *attemptState }
type attemptState struct {
	bindings AttemptBindings
	code     auth.OneTimeCode
}

// Bindings returns code-free immutable metadata for the trusted adapter. Zero
// returns ErrInvalidAttempt. It is not a wire format or dispatch capability.
func (a AttemptCommand) Bindings() (AttemptBindings, error) {
	if a.state == nil {
		return AttemptBindings{}, ErrInvalidAttempt
	}
	return a.state.bindings, nil
}

// Code borrows an opaque copy only for the counted locked comparison; no bytes
// are exposed. Release it immediately after comparison and never persist it.
// Zero returns ErrInvalidAttempt. Retained Go secrets cannot be fully erased.
func (a AttemptCommand) Code() (auth.OneTimeCode, error) {
	if a.state == nil {
		return auth.OneTimeCode{}, ErrInvalidAttempt
	}
	return a.state.code, nil
}

// Recovery returns the same exact code-free query identity on every call.
// Unknown outcomes must retain this identity, not prepare another submission.
// Zero returns ErrInvalidAttempt. This performs no lookup or reconciliation.
func (a AttemptCommand) Recovery() (AttemptRecoveryIdentity, error) {
	b, e := a.Bindings()
	if e != nil {
		return AttemptRecoveryIdentity{}, e
	}
	c, _ := b.Continuation.Bindings()
	return AttemptRecoveryIdentity{TenantID: identity.TenantID(c.Scope.TenantID), AttemptID: b.AttemptID, Fingerprint: b.Fingerprint, FingerprintKeyVersion: b.FingerprintKeyVersion}, nil
}
func (AttemptCommand) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.AttemptCommand(redacted)")
}
func (AttemptCommand) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AttemptCommand) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// AttemptIssuer owns a trusted independently generated fingerprint key and
// positive version. Use a key separate from challenge digest/signing keys.
// Zero is invalid. Copies retain secret material; concurrent calls own separate
// local buffers. No key accessor, background goroutine or synchronization owner.
type AttemptIssuer struct {
	version uint32
	key     [32]byte
}

// NewAttemptIssuer validates nonzero version/key without IO or retaining caller
// buffers. Rotation changes only newly prepared attempts; existing recovery
// identities must be looked up unchanged without the old key or submitted code.
// Same-version key replacement requires an explicit custody/migration decision.
func NewAttemptIssuer(version uint32, key [32]byte) (AttemptIssuer, error) {
	if version == 0 || key == ([32]byte{}) {
		return AttemptIssuer{}, ErrInvalidAttempt
	}
	return AttemptIssuer{version: version, key: key}, nil
}
func (AttemptIssuer) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.AttemptIssuer(redacted)")
}
func (AttemptIssuer) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (AttemptIssuer) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Prepare creates one logical submission with an unpredictable ID and a
// server-derived exact-input fingerprint. Call only after trusted continuation
// selection; no request-selected ID/fingerprint is accepted. Retry the same
// returned command or recover its original identity, never call Prepare again
// to recover ambiguity. This grants no challenge authority or durable outcome.
// Context is capped at five seconds and checked around bounded crypto/entropy;
// OS random reads cannot be forcibly interrupted. No weak fallback is used.
// The fingerprint binding is identity-otp-attempt-fingerprint-v1, NUL, uint32
// big-endian scope length, exact authorization-bound scope encoding, uint8 mode,
// uint64 expected version, uint32 fingerprint-key version, passed to opaque
// OneTimeCode.KeyedDigest. The ID uses exactly sixteen nonzero-total random bytes.
func (i AttemptIssuer) Prepare(ctx context.Context, c Continuation, mode AttemptMode, expectedVersion uint64, code auth.OneTimeCode) (AttemptCommand, error) {
	return i.prepare(ctx, rand.Reader, c, mode, expectedVersion, code)
}

func (i AttemptIssuer) prepare(ctx context.Context, entropy io.Reader, c Continuation, mode AttemptMode, expectedVersion uint64, code auth.OneTimeCode) (AttemptCommand, error) {
	if ctx == nil || entropy == nil || i.version == 0 || c.state == nil || expectedVersion == 0 || (mode != AttemptModeCheck && mode != AttemptModeConsume) {
		return AttemptCommand{}, ErrInvalidAttempt
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if e := ctx.Err(); e != nil {
		return AttemptCommand{}, e
	}
	b := []byte("identity-otp-attempt-fingerprint-v1\x00")
	b = binary.BigEndian.AppendUint32(b, uint32(len(c.state.scope.binding)))
	b = append(b, c.state.scope.binding...)
	b = append(b, byte(mode))
	b = binary.BigEndian.AppendUint64(b, expectedVersion)
	b = binary.BigEndian.AppendUint32(b, i.version)
	defer clear(b)
	fingerprint, e := code.KeyedDigest(i.key, b)
	if e != nil {
		return AttemptCommand{}, ErrInvalidAttempt
	}
	defer clear(fingerprint[:])
	var id [16]byte
	defer clear(id[:])
	_, e = io.ReadFull(entropy, id[:])
	if cancelErr := ctx.Err(); cancelErr != nil {
		return AttemptCommand{}, cancelErr
	}
	if e != nil || id == ([16]byte{}) {
		return AttemptCommand{}, ErrAttemptUnavailable
	}
	bindings := AttemptBindings{AttemptID: AttemptID(base64.RawURLEncoding.EncodeToString(id[:])), Fingerprint: AttemptFingerprint(base64.RawURLEncoding.EncodeToString(fingerprint[:])), FingerprintKeyVersion: i.version, Continuation: c, Mode: mode, ExpectedVersion: expectedVersion}
	return AttemptCommand{state: &attemptState{bindings: bindings, code: code}}, nil
}
