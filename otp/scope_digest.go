package otp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// StoredScopeDigest is adapter-only keyed correlation over the complete scope,
// not code verification, a bearer, a challenge digest or current authority.
// It lets storage match exact destination/workflow/authorization bindings without
// persisting plaintext destinations or an unkeyed dictionary-testable digest.
// KeyVersion is the explicit retained code-digest key version; protect both fields
// from telemetry. Unknown/retired keys deny rather than remapping old scope.
type StoredScopeDigest struct {
	KeyVersion uint32
	Value      [32]byte
}

// Format redacts private lookup data.
func (StoredScopeDigest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.StoredScopeDigest(redacted)")
}

// MarshalJSON denies automatic private lookup export.
func (StoredScopeDigest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText denies implicit private lookup export.
func (StoredScopeDigest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// ScopeDigest derives a code-free native storage binding under exactly the
// requested retained key version. Use the challenge's original code-digest key
// version, never silently substitute the current key on read or rotation.
// Framing is identity-otp-scope-digest-v1, NUL, uint32 big-endian complete scope
// byte length, scope bytes and uint32 big-endian key version, HMAC-SHA-256.
// Zero input returns ErrInvalidDigest; a missing retained version returns
// ErrDigestUnavailable. Bounded pure crypto, concurrent-safe, no IO or expiry
// renewal. A match does not replace primary replay, authority or attempt checks.
func (v Verifier) ScopeDigest(s DigestScope, version uint32) (StoredScopeDigest, error) {
	if v.current == 0 || s.binding == "" || version == 0 {
		return StoredScopeDigest{}, ErrInvalidDigest
	}
	key, ok := v.keys[version]
	if !ok {
		return StoredScopeDigest{}, ErrDigestUnavailable
	}
	frame := []byte("identity-otp-scope-digest-v1\x00")
	frame = binary.BigEndian.AppendUint32(frame, uint32(len(s.binding)))
	frame = append(frame, s.binding...)
	frame = binary.BigEndian.AppendUint32(frame, version)
	defer clear(frame)
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write(frame)
	result := StoredScopeDigest{KeyVersion: version}
	copy(result.Value[:], h.Sum(nil))
	return result, nil
}
