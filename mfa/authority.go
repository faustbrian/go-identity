// Package mfa owns second-factor authority and recovery policy. Primary
// passkey credentials are not automatically enrolled second factors.
package mfa

import (
	"fmt"
	"io"
	"strings"

	identity "github.com/faustbrian/go-identity"
)

// AuthorityRecord is a trusted store's current second-factor generation.
// ActiveFactors counts enrolled, confirmed factors, not pending enrollments or
// primary passkeys. Version starts at one and changes on every factor mutation.
// Missing storage must return an error, never synthesize an empty record.
// This structural value is not authentication or a portable authorization proof.
type AuthorityRecord struct {
	TenantID      identity.TenantID
	UserID        identity.UserID
	Version       uint64
	ActiveFactors uint32
}

// FactorAuthority is an immutable subject-bound view of current owner state.
// Zero is unknown and denies. It contains no factor secrets and is safe for
// concurrent reads. It has no renewable lease: consumers must read and fence
// authoritative state inside their protected transaction, not cache this value
// or accept it from a client. Construction alone does not prove store provenance.
type FactorAuthority struct{ record AuthorityRecord }

// NewFactorAuthority validates and copies trusted authoritative state. At most
// 64 active factors per account are supported. Invalid input returns only zero
// authority and a redacted error; no provider calls or cryptography occur.
func NewFactorAuthority(r AuthorityRecord) (FactorAuthority, error) {
	if _, err := identity.ParseIdentifierID(string(r.TenantID)); err != nil {
		return FactorAuthority{}, identity.InvalidInputError{Field: "factor_authority"}
	}
	if _, err := identity.ParseIdentifierID(string(r.UserID)); err != nil || r.Version == 0 || r.ActiveFactors > 64 {
		return FactorAuthority{}, identity.InvalidInputError{Field: "factor_authority"}
	}
	r.TenantID = identity.TenantID(strings.Clone(string(r.TenantID)))
	r.UserID = identity.UserID(strings.Clone(string(r.UserID)))
	return FactorAuthority{record: r}, nil
}

// Version returns the independent factor generation; zero means unknown.
func (s FactorAuthority) Version() uint64 { return s.record.Version }

// RequireEmailRecovery permits the no-factor recovery branch only for an
// explicitly known empty generation belonging to this exact subject. Enrolled,
// unknown or foreign state denies without falling back to another method.
// Verified email, account status, risk and purpose-bound capability admission
// remain separate required checks. A success is valid only while the caller's
// transaction retains the authoritative factor fence.
func (s FactorAuthority) RequireEmailRecovery(tenant identity.TenantID, user identity.UserID) error {
	if s.record.Version == 0 || s.record.TenantID != tenant || s.record.UserID != user || s.record.ActiveFactors != 0 {
		return identity.ForbiddenError{}
	}
	return nil
}

// Format intentionally omits subject and enrollment information.
func (AuthorityRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "mfa.AuthorityRecord(redacted)")
}

// Format intentionally omits subject and enrollment information.
func (FactorAuthority) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "mfa.FactorAuthority(redacted)")
}

// MarshalJSON rejects transport of internal authoritative state.
func (AuthorityRecord) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalJSON rejects transport of internal authoritative state.
func (FactorAuthority) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }
