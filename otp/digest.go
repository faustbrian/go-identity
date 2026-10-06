package otp

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"unicode"
	"unicode/utf8"

	auth "github.com/faustbrian/go-authentication"
)

var (
	// ErrInvalidDigest means invalid trusted scope, key configuration or code.
	// It deliberately includes no input or underlying credential error.
	ErrInvalidDigest = errors.New("otp: invalid digest input")
	// ErrDigestUnavailable means a recorded digest key is unknown or retired.
	// No fallback, rehash or successful comparison is performed.
	ErrDigestUnavailable = errors.New("otp: digest key unavailable")
	// ErrSensitiveSerialization denies automatic serialization of sensitive data.
	ErrSensitiveSerialization = errors.New("otp: sensitive serialization denied")
)

// Channel is a closed delivery channel, not proof of destination ownership.
type Channel string

const (
	// ChannelEmail selects email delivery; the owning workflow canonicalizes it.
	ChannelEmail Channel = "email"
	// ChannelSMS selects SMS delivery; the phone workflow enforces E.164.
	ChannelSMS Channel = "sms"
)

// DestinationInput owns bounded raw channel input. Zero is invalid. Copies
// share immutable secret storage; Go cannot guarantee its erasure. It is not
// a canonical address, unique identifier, ownership proof or delivery authority.
type DestinationInput struct{ value string }

// NewDestinationInput copies 1..320 UTF-8 bytes without control characters.
// Channel-specific canonicalization belongs to the owning workflow before
// scope creation. No parsing, normalization, IO or ownership lookup occurs.
func NewDestinationInput(value string) (DestinationInput, error) {
	if !boundedText(value, 320, false) {
		return DestinationInput{}, ErrInvalidDigest
	}
	return DestinationInput{value: strings.Clone(value)}, nil
}

// Value reveals raw channel input only for explicit trusted workflow/delivery
// composition. Do not log or persist it outside protected delivery custody.
func (d DestinationInput) Value() string { return d.value }

func (DestinationInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.DestinationInput(redacted)")
}
func (DestinationInput) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DestinationInput) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// DigestScopeSpec binds exact trusted canonical workflow data. TenantID,
// ChallengeID and TargetID are 1..256 UTF-8 bytes without controls; SubjectID
// may be empty for a pre-account challenge, otherwise has the same bound.
// Destination must already be canonicalized by the email/phone workflow.
// PolicyVersion and Generation are positive. AuthorizationBinding is a
// nonzero digest of the complete closed authorization context, including
// selected session remember policy where applicable. The owning workflow must
// derive it from verified context, not request input. It grants no authority.
// Changes to any field require a newly issued challenge; no scope migration
// is implicit. Do not format or serialize this projection; it contains PII.
type DigestScopeSpec struct {
	TenantID             string
	Purpose              Purpose
	SubjectID            string
	Channel              Channel
	Destination          DestinationInput
	ChallengeID          string
	TargetID             string
	PolicyVersion        uint64
	Generation           uint64
	AuthorizationBinding [32]byte
}

func (DigestScopeSpec) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.DigestScopeSpec(redacted)")
}
func (DigestScopeSpec) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DigestScopeSpec) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// DigestScope is immutable complete exact scope, safe for concurrent use.
// Zero is invalid. Construction validates syntax, not authorization or current
// challenge state; a matching digest remains a non-authoritative precheck.
type DigestScope struct{ binding string }

// NewDigestScope validates all bounds before encoding. Encoding is the literal
// identity-otp-code-scope-v1 and NUL, uint16 big-endian length-delimited exact
// tenant/purpose/subject/channel/destination/challenge/target strings, uint64
// big-endian policy/generation and 32 authorization bytes. The verifier appends
// uint32 big-endian key version. It is injective, versioned, and below the
// authentication binding limit. No caller buffer is retained.
func NewDigestScope(s DigestScopeSpec) (DigestScope, error) {
	if !boundedText(s.TenantID, 256, false) || !validPurpose(s.Purpose) ||
		!boundedText(s.SubjectID, 256, true) || (s.Channel != ChannelEmail && s.Channel != ChannelSMS) ||
		!boundedText(s.Destination.value, 320, false) || !boundedText(s.ChallengeID, 256, false) ||
		!boundedText(s.TargetID, 256, false) || s.PolicyVersion == 0 || s.Generation == 0 || s.AuthorizationBinding == ([32]byte{}) {
		return DigestScope{}, ErrInvalidDigest
	}
	b := []byte("identity-otp-code-scope-v1\x00")
	for _, value := range []string{s.TenantID, string(s.Purpose), s.SubjectID, string(s.Channel), s.Destination.value, s.ChallengeID, s.TargetID} {
		b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
		b = append(b, value...)
	}
	b = binary.BigEndian.AppendUint64(b, s.PolicyVersion)
	b = binary.BigEndian.AppendUint64(b, s.Generation)
	b = append(b, s.AuthorizationBinding[:]...)
	defer clear(b)
	return DigestScope{binding: string(b)}, nil
}

func boundedText(s string, max int, empty bool) bool {
	if len(s) > max || (!empty && len(s) == 0) || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (DigestScope) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "otp.DigestScope(redacted)") }
func (DigestScope) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (DigestScope) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// StoredCodeDigest is an explicit adapter-only digest projection, not a bearer
// or proof. Protect it from telemetry and unbounded online comparison. Unknown
// key versions deny; storage migration preserves original bytes/version and
// scope. Never regenerate a digest without a fresh secret submission.
type StoredCodeDigest struct {
	KeyVersion uint32
	Value      [32]byte
}

func (StoredCodeDigest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "otp.StoredCodeDigest(redacted)")
}
func (StoredCodeDigest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (StoredCodeDigest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// CodeDigest is immutable scoped storage data. Zero is invalid. It does not
// issue a challenge or prove a successful counted attempt or consumption.
type CodeDigest struct{ stored StoredCodeDigest }

// Storage returns explicit digest-only persistence data; never log it.
func (d CodeDigest) Storage() StoredCodeDigest  { return d.stored }
func (CodeDigest) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "otp.CodeDigest(redacted)") }
func (CodeDigest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (CodeDigest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Verifier owns an immutable retained key ring. Zero is invalid; copies retain
// key material. It performs pure bounded keyed comparison, not authentication,
// rate limiting, expiry checks, reservation or state changes. Call Compare only
// within an authoritative counted attempt transaction, after checking locked
// challenge scope, expiry, generation and current authorization. Successful
// non-consuming checks must never mint a proof/reservation. No IO or goroutines.
type Verifier struct {
	current uint32
	keys    map[uint32][32]byte
}

// NewVerifier copies 1..8 independently generated nonzero 32-byte keys with
// positive versions and an explicit retained current version. Reconstruct with
// a new current key to rotate; retain earlier keys through challenge retention.
// Removing a key fails closed for its outstanding challenges, without fallback.
// Key custody changes under an existing version require an explicit migration
// decision; this constructor cannot validate historical key custody.
func NewVerifier(current uint32, keys map[uint32][32]byte) (Verifier, error) {
	if current == 0 || len(keys) < 1 || len(keys) > 8 || keys[current] == ([32]byte{}) {
		return Verifier{}, ErrInvalidDigest
	}
	for version, key := range keys {
		if version == 0 || key == ([32]byte{}) {
			return Verifier{}, ErrInvalidDigest
		}
	}
	return Verifier{current: current, keys: maps.Clone(keys)}, nil
}

func (Verifier) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "otp.Verifier(redacted)") }
func (Verifier) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (Verifier) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Digest uses the configured current key and exact scope; a zero verifier,
// scope or opaque code returns ErrInvalidDigest. Code bytes remain inside
// authentication. The result grants no issuance or authentication authority.
func (v Verifier) Digest(s DigestScope, code auth.OneTimeCode) (CodeDigest, error) {
	value, e := v.derive(s, v.current, code)
	if e != nil {
		return CodeDigest{}, e
	}
	return CodeDigest{stored: StoredCodeDigest{KeyVersion: v.current, Value: value}}, nil
}

// Compare derives with exactly the stored key version and constant-time
// compares the two fixed-size digests. Mismatched code/scope returns false,nil.
// Invalid zero inputs return ErrInvalidDigest; missing/retired positive versions
// return ErrDigestUnavailable. No timing, attempts or challenge state are
// renewed. This method is not a public unmetered code-check endpoint.
func (v Verifier) Compare(s DigestScope, stored StoredCodeDigest, code auth.OneTimeCode) (bool, error) {
	if stored.KeyVersion == 0 || stored.Value == ([32]byte{}) {
		return false, ErrInvalidDigest
	}
	value, e := v.derive(s, stored.KeyVersion, code)
	if e != nil {
		return false, e
	}
	return hmac.Equal(value[:], stored.Value[:]), nil
}

func (v Verifier) derive(s DigestScope, version uint32, code auth.OneTimeCode) ([32]byte, error) {
	if v.current == 0 || s.binding == "" || version == 0 {
		return [32]byte{}, ErrInvalidDigest
	}
	key, ok := v.keys[version]
	if !ok {
		return [32]byte{}, ErrDigestUnavailable
	}
	b := binary.BigEndian.AppendUint32([]byte(s.binding), version)
	defer clear(b)
	d, e := code.KeyedDigest(key, b)
	if e != nil {
		return [32]byte{}, ErrInvalidDigest
	}
	return d, nil
}
