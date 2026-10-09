// Package password owns identity password workflows, not hashing primitives or
// address-kind canonicalization. Workflow composition is still in development.
package password

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"unicode/utf8"

	primitive "github.com/faustbrian/go-password"
)

var (
	// ErrInvalidPolicy rejects missing, reversed or unbounded byte limits.
	ErrInvalidPolicy = errors.New("identity.password.invalid_policy")
	// ErrRegistrationDisabled denies signup under an explicitly disabled policy.
	ErrRegistrationDisabled = errors.New("identity.password.registration_disabled")
	// ErrInvalidPassword rejects absent/destroyed secrets or raw byte bounds.
	// It reveals neither password material nor which bound was violated.
	ErrInvalidPassword = errors.New("identity.password.invalid_password")
	// ErrInvalidSignupAddress rejects missing, oversized or malformed UTF-8 input.
	ErrInvalidSignupAddress = errors.New("identity.password.invalid_signup_address")
	// ErrSensitiveSerialization prevents implicit address disclosure.
	ErrSensitiveSerialization = errors.New("identity.password.sensitive_serialization")
)

// RegistrationPolicy is explicit deployment input. Validate requires raw byte
// limits in 1..1,048,576, maximum at least minimum, even when disabled. Zero is
// invalid. False Enabled explicitly disables signup; false RequireVerifiedEmail
// does not require prior verification. The registration workflow owns applying
// verification policy; byte admission alone proves no identity or authority.
// Value copies are independent and safe for concurrent reads; callers must not
// mutate the same policy concurrently. Services must freeze their input copy.
type RegistrationPolicy struct {
	Enabled              bool
	MinimumBytes         uint32
	MaximumBytes         uint32
	RequireVerifiedEmail bool
}

// Validate checks intrinsic limits without IO, allocation, hashing or defaults.
// The reference deployment owns its stricter minimum/maximum policy ranges.
func (p RegistrationPolicy) Validate() error {
	if p.MinimumBytes == 0 || p.MaximumBytes < p.MinimumBytes || p.MaximumBytes > 1<<20 {
		return ErrInvalidPolicy
	}
	return nil
}

// CheckPassword admits only enabled registration and a currently live primitive
// Secret within inclusive raw byte limits. It does not trim, normalize, copy,
// borrow, hash or destroy the caller's secret. A successful check is a momentary
// length observation, not a lease: hashing must still use Secret.Use and honor
// its destruction/concurrent-borrow rejection. This is not a HIBP/risk decision
// or permission to persist a hash or issue a session.
func (p RegistrationPolicy) CheckPassword(secret primitive.Secret) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if !p.Enabled {
		return ErrRegistrationDisabled
	}
	length := secret.Len()
	if length < int(p.MinimumBytes) || length > int(p.MaximumBytes) {
		return ErrInvalidPassword
	}
	return nil
}

// SignupAddressInput is generic unnormalized UTF-8 input, 1..4096 bytes. The
// registration owner interprets its address kind, canonicalization, uniqueness
// and verification; this package must not parse it as an email address. Direct
// conversions require Validate at workflow admission. Explicit string conversion
// reveals sensitive input. Ordinary direct diagnostics redact and serialization
// denies; do not place a raw scalar in private diagnostic fields where fmt can
// bypass its methods. This input is never address ownership or authentication.
type SignupAddressInput string

// Validate enforces only raw UTF-8 byte bounds, not address-kind semantics. It
// preserves every accepted byte for the configured registration owner.
func (a SignupAddressInput) Validate() error {
	if len(a) == 0 || len(a) > 4096 || !utf8.ValidString(string(a)) {
		return ErrInvalidSignupAddress
	}
	return nil
}

// Format prevents direct diagnostic formatting from revealing address input.
func (SignupAddressInput) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "password.SignupAddressInput(redacted)")
}

// LogValue prevents structured logging from implicitly projecting the address.
func (SignupAddressInput) LogValue() slog.Value {
	return slog.StringValue("password.SignupAddressInput(redacted)")
}

// MarshalJSON rejects implicit address disclosure, including invalid inputs.
func (SignupAddressInput) MarshalJSON() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}

// MarshalText rejects implicit text/map-key serialization of address input.
func (SignupAddressInput) MarshalText() ([]byte, error) {
	return nil, ErrSensitiveSerialization
}
