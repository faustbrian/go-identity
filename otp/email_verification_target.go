package otp

import (
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// EmailVerificationRecoveryPath is the canonical, non-fallback recovery selector
// for this verification-only OTP workflow. It is not an authentication assertion.
const EmailVerificationRecoveryPath = "email_verification_otp"

// EmailVerificationTargetSpec freezes one real managed pending email, its two
// equal positive versions and known-empty factor generation. Tenant, subject
// and the independent send request belong to the surrounding OTP scope. These
// fields nor construction prove that the rows exist, are pending or authorized.
// The native owner must resolve and compare every value before issuance and in
// the protected mutation. Maximum uint64 versions cannot produce successors.
type EmailVerificationTargetSpec struct {
	IdentifierID                           identity.IdentifierID
	IdentifierVersion, VerificationVersion uint64
	FactorVersion                          uint64
}

// EmailVerificationTarget is immutable, code-free sensitive workflow scope.
// Copies own no resources and permit concurrent reads. Zero denies. The canonical
// selector is selected before issuance, then carried by the existing OTP TargetID
// and scope digest through reservation/finalization; it is never a link alias.
type EmailVerificationTarget struct{ state *emailVerificationTargetState }

type emailVerificationTargetState struct {
	read   func() EmailVerificationTargetSpec
	target func() string
}

// NewEmailVerificationTarget validates bounds before formatting and freezes the
// canonical target without IO, entropy, normalization or granting authority.
// The identifier is length-framed so punctuation never creates another target.
func NewEmailVerificationTarget(s EmailVerificationTargetSpec) (EmailVerificationTarget, error) {
	if len(s.IdentifierID) == 0 || len(s.IdentifierID) > 128 || s.IdentifierVersion == 0 || s.IdentifierVersion == ^uint64(0) || s.VerificationVersion != s.IdentifierVersion || s.FactorVersion == 0 || s.FactorVersion == ^uint64(0) {
		return EmailVerificationTarget{}, ErrInvalidAttempt
	}
	if _, err := identity.ParseIdentifierID(string(s.IdentifierID)); err != nil {
		return EmailVerificationTarget{}, ErrInvalidAttempt
	}
	s.IdentifierID = identity.IdentifierID(strings.Clone(string(s.IdentifierID)))
	raw := EmailVerificationRecoveryPath + ":" + strconv.Itoa(len(s.IdentifierID)) + ":" + string(s.IdentifierID) + ":" + strconv.FormatUint(s.IdentifierVersion, 10) + ":" + strconv.FormatUint(s.VerificationVersion, 10) + ":" + strconv.FormatUint(s.FactorVersion, 10)
	if len(raw) > 256 {
		return EmailVerificationTarget{}, ErrInvalidAttempt
	}
	return EmailVerificationTarget{state: &emailVerificationTargetState{read: func() EmailVerificationTargetSpec { return s }, target: func() string { return raw }}}, nil
}

// ParseEmailVerificationTarget admits only the bounded canonical spelling of
// this exact selector and profile. It does not authenticate an OTP challenge,
// read an address, renew authority or admit a protected mutation.
func ParseEmailVerificationTarget(raw string) (EmailVerificationTarget, error) {
	bad := func() (EmailVerificationTarget, error) { return EmailVerificationTarget{}, ErrInvalidAttempt }
	if len(raw) == 0 || len(raw) > 256 {
		return bad()
	}
	rest, ok := strings.CutPrefix(raw, EmailVerificationRecoveryPath+":")
	if !ok {
		return bad()
	}
	length, rest, ok := strings.Cut(rest, ":")
	n, err := strconv.Atoi(length)
	if !ok || err != nil || n < 1 || n > 128 || strconv.Itoa(n) != length || len(rest) <= n || rest[n] != ':' {
		return bad()
	}
	id := rest[:n]
	parts := strings.Split(rest[n+1:], ":")
	if len(parts) != 3 {
		return bad()
	}
	var versions [3]uint64
	for i := range versions {
		value, err := strconv.ParseUint(parts[i], 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != parts[i] {
			return bad()
		}
		versions[i] = value
	}
	target, err := NewEmailVerificationTarget(EmailVerificationTargetSpec{IdentifierID: identity.IdentifierID(id), IdentifierVersion: versions[0], VerificationVersion: versions[1], FactorVersion: versions[2]})
	if err != nil {
		return bad()
	}
	canonical, _ := target.ScopeTarget()
	if canonical != raw {
		return bad()
	}
	return target, nil
}

// Bindings explicitly returns sensitive code-free correlation, not authority.
func (t EmailVerificationTarget) Bindings() (EmailVerificationTargetSpec, error) {
	if t.state == nil {
		return EmailVerificationTargetSpec{}, ErrInvalidAttempt
	}
	return t.state.read(), nil
}

// ScopeTarget explicitly returns the bounded native OTP TargetID projection.
// Never log or expose it as successful verification or a session credential.
func (t EmailVerificationTarget) ScopeTarget() (string, error) {
	if t.state == nil {
		return "", ErrInvalidAttempt
	}
	return t.state.target(), nil
}

// Format redacts target identity and versions, including Go-syntax diagnostics.
func (EmailVerificationTarget) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailVerificationTarget(redacted)"))
}

// LogValue returns only a constant marker.
func (EmailVerificationTarget) LogValue() slog.Value {
	return slog.StringValue("otp.EmailVerificationTarget(redacted)")
}

// MarshalJSON rejects implicit export of private correlation.
func (EmailVerificationTarget) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }

// MarshalText rejects implicit text and map-key export.
func (EmailVerificationTarget) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// Format redacts explicit native target specifications.
func (EmailVerificationTargetSpec) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.EmailVerificationTargetSpec(redacted)"))
}

// MarshalJSON rejects accidental specification export.
func (EmailVerificationTargetSpec) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects accidental specification export.
func (EmailVerificationTargetSpec) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
