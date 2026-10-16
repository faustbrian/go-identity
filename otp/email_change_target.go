package otp

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log/slog"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// EmailChangeRecoveryPath selects primary replacement by independently issued
// new-address OTP. It is distinct from verification-only email recovery and
// cannot reinterpret a link or authenticate a user.
const EmailChangeRecoveryPath = "email_change_otp"

// EmailChangeTargetSpec conserves one actual committed change origin and its
// pending candidate/factor generations. OriginOutputDigest is SHA-256 of the
// exact authenticated encrypted original change output, including old-address,
// policy, source session and validity custody; the native origin owner reads
// and authenticates that output before constructing this value. A caller hash
// or current pending address is not original authority. Tenant, subject and
// independently issued OTP command are additionally bound by the OTP scope.
// Construction validates shape only; it grants no proof or mutation permission.
type EmailChangeTargetSpec struct {
	OriginCommandID                        identity.CommandID
	OriginOutputDigest                     [32]byte
	IdentifierID                           identity.IdentifierID
	IdentifierVersion, VerificationVersion uint64
	FactorVersion                          uint64
}

// EmailChangeTarget is immutable sensitive original-change correlation. Copies
// own no resources and support concurrent reads; zero denies. The fixed-size
// versioned digest commits the complete framed input without narrowing the
// existing 128-byte identifier contract to fit OTP's 256-byte TargetID bound.
// The original native owner must reconstruct and compare it during issuance,
// completion and recovery. Only the original command locator is decodable, not
// replacement intent or authority; no separate correlation store is required.
type EmailChangeTarget struct{ state *emailChangeTargetState }

type emailChangeTargetState struct {
	spec  EmailChangeTargetSpec
	scope string
}

// NewEmailChangeTarget freezes structurally valid original correlation without
// IO, normalization, entropy or authority renewal. Pending versions must be
// equal and positive; terminal maximum generations cannot produce a successor.
// Hashing is only a domain-separated intent commitment, not authentication or
// OTP verification; existing native code digests remain independently keyed.
func NewEmailChangeTarget(s EmailChangeTargetSpec) (EmailChangeTarget, error) {
	if s.OriginOutputDigest == ([32]byte{}) || len(s.IdentifierID) == 0 || len(s.IdentifierID) > 128 || s.IdentifierVersion == 0 || s.IdentifierVersion == ^uint64(0) || s.VerificationVersion != s.IdentifierVersion || s.FactorVersion == 0 || s.FactorVersion == ^uint64(0) {
		return EmailChangeTarget{}, ErrInvalidAttempt
	}
	if _, err := identity.ParseCommandID(string(s.OriginCommandID)); err != nil {
		return EmailChangeTarget{}, ErrInvalidAttempt
	}
	if _, err := identity.ParseIdentifierID(string(s.IdentifierID)); err != nil {
		return EmailChangeTarget{}, ErrInvalidAttempt
	}
	s.OriginCommandID = identity.CommandID(strings.Clone(string(s.OriginCommandID)))
	s.IdentifierID = identity.IdentifierID(strings.Clone(string(s.IdentifierID)))
	frame := []byte("identity-email-change-otp-target-v1\x00")
	for _, value := range []string{string(s.OriginCommandID), string(s.IdentifierID)} {
		frame = binary.BigEndian.AppendUint16(frame, uint16(len(value)))
		frame = append(frame, value...)
	}
	frame = append(frame, s.OriginOutputDigest[:]...)
	for _, version := range []uint64{s.IdentifierVersion, s.VerificationVersion, s.FactorVersion} {
		frame = binary.BigEndian.AppendUint64(frame, version)
	}
	digest := sha256.Sum256(frame)
	clear(frame)
	scope := EmailChangeRecoveryPath + ":v1:" + string(s.OriginCommandID) + ":" + base64.RawURLEncoding.EncodeToString(digest[:])
	return EmailChangeTarget{state: &emailChangeTargetState{spec: s, scope: scope}}, nil
}

// EmailChangeOriginCommand parses only the bounded original request locator.
// It performs no IO or authentication; fabricated commitments can parse. The
// native workflow must read authentic committed change custody and reconstruct
// the complete target before issuance, comparison, mutation or recovery. A
// locator, pending address or digest equality alone grants no permission.
func EmailChangeOriginCommand(scopeTarget string) (identity.CommandID, error) {
	const prefix = EmailChangeRecoveryPath + ":v1:"
	// Canonical command IDs are 22 bytes and SHA-256 raw URL encodings 43 bytes.
	// Bound before splitting or decoding any untrusted data.
	if len(scopeTarget) != len(prefix)+22+1+43 || !strings.HasPrefix(scopeTarget, prefix) {
		return "", ErrInvalidAttempt
	}
	parts := strings.Split(scopeTarget[len(prefix):], ":")
	if len(parts) != 2 {
		return "", ErrInvalidAttempt
	}
	command, err := identity.ParseCommandID(parts[0])
	if err != nil {
		return "", ErrInvalidAttempt
	}
	digest, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(digest) != sha256.Size || base64.RawURLEncoding.EncodeToString(digest) != parts[1] {
		return "", ErrInvalidAttempt
	}
	return identity.CommandID(strings.Clone(string(command))), nil
}

// Bindings explicitly returns code-free private correlation, never permission.
func (t EmailChangeTarget) Bindings() (EmailChangeTargetSpec, error) {
	if t.state == nil {
		return EmailChangeTargetSpec{}, ErrInvalidAttempt
	}
	return t.state.spec, nil
}

// ScopeTarget returns the bounded original OTP TargetID commitment. Neither
// possession nor equality proves current change/factor/session authority.
func (t EmailChangeTarget) ScopeTarget() (string, error) {
	if t.state == nil {
		return "", ErrInvalidAttempt
	}
	return t.state.scope, nil
}

// Format exposes only a constant diagnostic marker.
func (EmailChangeTarget) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailChangeTarget(redacted)"))
}

// LogValue prevents structured logging from disclosing original correlation.
func (EmailChangeTarget) LogValue() slog.Value {
	return slog.StringValue("otp.EmailChangeTarget(redacted)")
}

// MarshalJSON rejects implicit private-correlation export.
func (EmailChangeTarget) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit private-correlation and map-key export.
func (EmailChangeTarget) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts explicit native target specifications.
func (EmailChangeTargetSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailChangeTargetSpec(redacted)"))
}

// LogValue redacts original intent from structured diagnostics.
func (EmailChangeTargetSpec) LogValue() slog.Value {
	return slog.StringValue("otp.EmailChangeTargetSpec(redacted)")
}

// MarshalJSON rejects implicit original-intent export.
func (EmailChangeTargetSpec) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit original-intent and map-key export.
func (EmailChangeTargetSpec) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }
