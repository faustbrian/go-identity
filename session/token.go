package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
)

var (
	// ErrInvalidToken rejects invalid size, zero or noncanonical bearers without
	// disclosing input. Token construction alone proves no session authority.
	ErrInvalidToken = errors.New("session: invalid token")
	// ErrTokenAlreadyRevealed denies another delivery through any value copy.
	ErrTokenAlreadyRevealed = errors.New("session: token already revealed")
	// ErrInvalidDigest rejects invalid lookup scope or uninitialized digest keys.
	ErrInvalidDigest = errors.New("session: invalid digest input")
	// ErrSecretSerialization prevents automatic JSON/text disclosure of custody.
	ErrSecretSerialization = errors.New("session: secret serialization forbidden")
)

// Token owns an opaque 32..64-byte bearer encoded as canonical unpadded
// base64url. Zero is invalid. No raw secret is exposed by formatting or automatic
// serialization. Copies share one atomic Reveal permission; Digest is read-only
// and concurrency-safe before and after Reveal. Token owns no external resource.
// It cannot prove authentication, authority, persistence or session expiry.
type Token struct{ state *tokenState }

type tokenState struct {
	wire     string
	revealed atomic.Bool
}

// NewToken creates a cryptographically random token of exactly size bytes,
// bounded to 32..64 before allocation. Go's crypto/rand owns secure OS entropy;
// fatal entropy failure follows its standard fail-stop behavior. This allocates
// a credential only, not a session, command, receipt or database row. Reveal only
// after the authoritative issuance transaction commits; unknown outcomes must
// reveal nothing. Durable recovery must recover the original issuance result,
// never call NewToken to retry an ambiguous command.
func NewToken(size int) (Token, error) {
	if size < 32 || size > 64 {
		return Token{}, ErrInvalidToken
	}
	raw := make([]byte, size)
	rand.Read(raw)
	return Token{state: &tokenState{wire: base64.RawURLEncoding.EncodeToString(raw)}}, nil
}

// ParseToken copies a bounded canonical bearer from an explicit credential
// transport. Padding, whitespace, non-URL alphabet, trailing bits and decoded
// lengths outside 32..64 deny. Parsing creates one new delivery permission:
// callers already possessing wire bytes can parse again, so Reveal is custody
// control, not a replay store or cryptographic limit on bearer reuse.
func ParseToken(wire string) (Token, error) {
	if len(wire) < 43 || len(wire) > 86 {
		return Token{}, ErrInvalidToken
	}
	raw, e := base64.RawURLEncoding.Strict().DecodeString(wire)
	if e != nil || len(raw) < 32 || len(raw) > 64 || base64.RawURLEncoding.EncodeToString(raw) != wire {
		return Token{}, ErrInvalidToken
	}
	return Token{state: &tokenState{wire: strings.Clone(wire)}}, nil
}

// Reveal returns the credential exactly once across copies. The atomic claim
// occurs before return; lost delivery does not restore it. The transport must
// never log, persist raw, snapshot or encode the returned value outside the
// explicitly authorized credential response/cookie/header. This does not erase
// process memory or prevent a recipient from retaining the credential.
func (t Token) Reveal() (string, error) {
	if t.state == nil {
		return "", ErrInvalidToken
	}
	if !t.state.revealed.CompareAndSwap(false, true) {
		return "", ErrTokenAlreadyRevealed
	}
	return t.state.wire, nil
}

// Format redacts for every fmt verb, including quoted and Go-syntax output.
func (t Token) Format(s fmt.State, _ rune) { io.WriteString(s, "[REDACTED]") }

// MarshalJSON denies accidental bearer serialization. Explicit Reveal is the
// sole transport disclosure operation.
func (t Token) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies text and map-key serialization of bearer custody.
func (t Token) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// DigestKey owns a defensive immutable copy of 32..64 key bytes and a positive
// rotation version. Zero is invalid; fmt/JSON/text operations never disclose it.
// Use independent CSPRNG-derived session-lookup material, not capability signing,
// password, API-key or envelope keys. This is in-memory key custody, not durable
// encrypted storage or a key provider. The deployment owns rotation/retirement.
type DigestKey struct{ state *digestKeyState }

// Pointer custody avoids inline material exposure when fmt skips methods on
// an enclosing struct's unexported fields. The state is immutable after minting.
type digestKeyState struct {
	material [64]byte
	size     uint8
	version  uint32
}

// NewDigestKey copies key material after bounded validation. The caller owns
// source-buffer erasure and cryptographic entropy. Versions must never be reused
// for different material; retain old keys while their session/tombstone lookup
// paths remain required. Key generation and provider readiness are composition.
func NewDigestKey(version uint32, material []byte) (DigestKey, error) {
	if version == 0 || len(material) < 32 || len(material) > 64 {
		return DigestKey{}, ErrInvalidDigest
	}
	s := &digestKeyState{size: uint8(len(material)), version: version}
	copy(s.material[:], material)
	return DigestKey{state: s}, nil
}

// Format redacts all key formatting.
func (k DigestKey) Format(s fmt.State, _ rune) { io.WriteString(s, "[REDACTED]") }

// MarshalJSON denies key serialization.
func (k DigestKey) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText denies text and map-key key serialization.
func (k DigestKey) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }

// TokenDigest is the non-bearer lookup projection. KeyVersion and all 32 digest
// bytes must be persisted together with tenant scope. It is not authentication
// proof and must not be exposed as an alternate client credential. Avoid logging
// stable lookup digests because they correlate session activity.
type TokenDigest struct {
	KeyVersion uint32
	Sum        [32]byte
}

// Digest computes HMAC-SHA-256 over the exact framing:
// "golib-session-lookup-v1\x00", big-endian uint32 key version, big-endian uint16
// tenant-byte length, tenant bytes, uint8 decoded-token length, decoded bytes.
// Tenant is an already canonical 1..128-byte visible ASCII ID, never a user-input
// normalizer. Scope/domain/version separation is mandatory. No raw token or key
// is retained in the returned value. Rotating keys requires explicit lookups
// with each required retained key; this method does not silently change versions.
func (t Token) Digest(k DigestKey, tenant string) (TokenDigest, error) {
	if t.state == nil {
		return TokenDigest{}, ErrInvalidToken
	}
	if k.state == nil || len(tenant) == 0 || len(tenant) > 128 {
		return TokenDigest{}, ErrInvalidDigest
	}
	for i := range len(tenant) {
		if tenant[i] < 33 || tenant[i] > 126 {
			return TokenDigest{}, ErrInvalidDigest
		}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(t.state.wire)
	h := hmac.New(sha256.New, k.state.material[:k.state.size])
	h.Write([]byte("golib-session-lookup-v1\x00"))
	var header [6]byte
	binary.BigEndian.PutUint32(header[:4], k.state.version)
	binary.BigEndian.PutUint16(header[4:], uint16(len(tenant)))
	h.Write(header[:])
	h.Write([]byte(tenant))
	h.Write([]byte{byte(len(raw))})
	h.Write(raw)
	d := TokenDigest{KeyVersion: k.state.version}
	copy(d.Sum[:], h.Sum(nil))
	return d, nil
}
