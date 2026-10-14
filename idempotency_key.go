package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
)

// IdempotencyKey owns a transient immutable client retry key with no raw
// accessor. Zero is invalid; copies are comparable and safe for concurrent
// digesting. Equality identifies the same constructed owner, not equal bytes;
// independently constructed keys may be correlated only by scoped digests.
// Retain only keyed digests in durable mappings. Dropping references
// does not guarantee erasure of immutable strings or caller-owned copies.
type IdempotencyKey struct{ state *idempotencyKeyState }

// A closure prevents fmt's recursive reflection of private caller fields,
// including unsupported-verb pointer diagnostics, from reaching raw bytes.
// Owner indirection retains comparability without exposing content equality.
type idempotencyKeyState struct{ raw func() string }

// NewIdempotencyKey copies exactly 1..256 ASCII HTTP token bytes: letters,
// digits and !#$%&'*+-.^_`|~. Spaces, commas, quotes, controls, non-ASCII bytes
// and separators deny. There is no trimming, case folding or normalization.
// InvalidInputError is redacted. HTTP adapters separately reject duplicate
// headers and keys supplied anywhere other than the single permitted header.
// This pure constructor performs no I/O or authentication.
func NewIdempotencyKey(raw []byte) (IdempotencyKey, error) {
	if len(raw) < 1 || len(raw) > 256 {
		return IdempotencyKey{}, InvalidInputError{Field: "idempotency_key"}
	}
	for _, b := range raw {
		if !requestKeyTokenByte(b) {
			return IdempotencyKey{}, InvalidInputError{Field: "idempotency_key"}
		}
	}
	owned := string(raw)
	return IdempotencyKey{state: &idempotencyKeyState{raw: func() string { return owned }}}, nil
}

// Digest returns HMAC-SHA-256 under a nonzero authority-owned 32-byte lookup
// key over "golib.identity.request-key.v1\x00", unsigned 64-bit big-endian raw
// length and exact raw bytes. It conveys no authorization or command outcome.
// The consuming adapter owns tenant/actor/method/route scoping and immutable
// lookup-key namespace; rotating this key cannot silently reassign old retries.
// Zero client or authority keys return redacted InvalidInputError. No I/O runs.
func (k IdempotencyKey) Digest(authorityKey [32]byte) ([32]byte, error) {
	if k.state == nil || authorityKey == ([32]byte{}) {
		return [32]byte{}, InvalidInputError{Field: "idempotency_key"}
	}
	mac := hmac.New(sha256.New, authorityKey[:])
	_, _ = io.WriteString(mac, "golib.identity.request-key.v1\x00")
	raw := k.state.raw()
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(raw)))
	_, _ = mac.Write(length[:])
	_, _ = io.WriteString(mac, raw)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}

func requestKeyTokenByte(b byte) bool {
	if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
		return true
	}
	switch b {
	case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	}
	return false
}

// Format never reveals raw client bytes for any diagnostic verb.
func (IdempotencyKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.IdempotencyKey(redacted)")
}

// MarshalJSON rejects implicit key persistence or HTTP disclosure.
func (IdempotencyKey) MarshalJSON() ([]byte, error) {
	return nil, InvalidInputError{Field: "idempotency_key_serialization"}
}

// MarshalText rejects text and map-key serialization.
func (IdempotencyKey) MarshalText() ([]byte, error) {
	return nil, InvalidInputError{Field: "idempotency_key_serialization"}
}

// LogValue emits a constant independent of client bytes or validity.
func (IdempotencyKey) LogValue() slog.Value {
	return slog.StringValue("identity.IdempotencyKey(redacted)")
}
