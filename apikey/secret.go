package apikey

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
)

// Secret owns exactly 32 random bytes in the fixed idk_ canonical base64url
// profile. Copies share one reveal claim. No serialization or diagnostic method
// exposes the wire value. The caller retains custody only for its issuance call;
// adapters must never put it in durable preparations, journals or results.
type Secret struct{ state *secretState }
type secretState struct {
	wire     string
	revealed atomic.Bool
}

// GenerateSecret uses the standard CSPRNG without modulo bias. Entropy failure
// follows crypto/rand's fail-stop semantics. This creates no persistent key.
func GenerateSecret() (Secret, error) {
	var raw [32]byte
	rand.Read(raw[:])
	return Secret{state: &secretState{wire: "idk_" + base64.RawURLEncoding.EncodeToString(raw[:])}}, nil
}

// ParseSecret bounds input before decoding and rejects noncanonical trailing
// bits, padding and aliases. It proves no authentication or current authority.
func ParseSecret(wire string) (Secret, error) {
	if len(wire) != 47 || !strings.HasPrefix(wire, "idk_") {
		return Secret{}, ErrInvalid
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(wire[4:])
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != wire[4:] {
		return Secret{}, ErrInvalid
	}
	return Secret{state: &secretState{wire: strings.Clone(wire)}}, nil
}

// Reveal claims the single response delivery before returning. Lost delivery
// never resets the claim; invoke only after proven commit, never on recovery.
func (s Secret) Reveal() (string, error) {
	if s.state == nil {
		return "", ErrInvalid
	}
	if !s.state.revealed.CompareAndSwap(false, true) {
		return "", ErrAlreadyRevealed
	}
	return s.state.wire, nil
}
func (Secret) Format(s fmt.State, _ rune)   { io.WriteString(s, "[REDACTED]") }
func (Secret) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (Secret) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (Secret) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }

// Pepper is immutable versioned 32-byte material, distinct from session,
// command-fingerprint, signing and envelope keys. Deployment owns entropy,
// envelope custody, version uniqueness and retention for live old revisions.
type Pepper struct{ state *pepperState }
type pepperState struct {
	version  uint32
	material [32]byte
}

func NewPepper(version uint32, material []byte) (Pepper, error) {
	if version == 0 || len(material) != 32 {
		return Pepper{}, ErrInvalid
	}
	p := &pepperState{version: version}
	copy(p.material[:], material)
	return Pepper{state: p}, nil
}
func (Pepper) Format(s fmt.State, _ rune)   { io.WriteString(s, "[REDACTED]") }
func (Pepper) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (Pepper) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
func (Pepper) LogValue() slog.Value         { return slog.StringValue("[REDACTED]") }

// Digest is nonrecoverable lookup metadata, never an alternate bearer. Persist
// all fields and exact tenant/configuration scope together; do not log it.
type Digest struct {
	PepperVersion uint32
	Sum           [32]byte
}

func (d Digest) Equal(other Digest) bool {
	var a, b [36]byte
	binary.BigEndian.PutUint32(a[:4], d.PepperVersion)
	copy(a[4:], d.Sum[:])
	binary.BigEndian.PutUint32(b[:4], other.PepperVersion)
	copy(b[4:], other.Sum[:])
	return hmac.Equal(a[:], b[:])
}
func (d Digest) Validate() error {
	if d.PepperVersion == 0 || d.Sum == ([32]byte{}) {
		return ErrInvalid
	}
	return nil
}
func (Digest) Format(s fmt.State, _ rune)   { io.WriteString(s, "apikey.Digest(redacted)") }
func (Digest) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// Digest computes HMAC-SHA-256 with domain and unambiguous length framing over
// pepper version, tenant, stored configuration ID/revision and issuer bindings,
// then the full canonical secret. The configuration, not the prefix, selects
// verification policy. Digest remains usable after Reveal but cannot reveal.
func (s Secret) Digest(p Pepper, tenant string, c Configuration) (Digest, error) {
	if s.state == nil || p.state == nil || !scope(tenant, 128) || c.Validate() != nil {
		return Digest{}, ErrInvalid
	}
	h := hmac.New(sha256.New, p.state.material[:])
	h.Write([]byte("golib-api-key-modern-v1\x00"))
	var number [8]byte
	binary.BigEndian.PutUint32(number[:4], p.state.version)
	h.Write(number[:4])
	binary.BigEndian.PutUint64(number[:], c.spec.Revision)
	h.Write(number[:])
	for _, value := range []string{tenant, c.spec.ID, c.spec.Issuer, c.spec.Environment, c.spec.Audience, s.state.wire} {
		binary.BigEndian.PutUint32(number[:4], uint32(len(value)))
		h.Write(number[:4])
		h.Write([]byte(value))
	}
	d := Digest{PepperVersion: p.state.version}
	copy(d.Sum[:], h.Sum(nil))
	return d, nil
}
