package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// ErrCredentialAuthority denies incomplete, stale, inactive or mismatched
// credential eligibility without identifying the failing field or credential.
var ErrCredentialAuthority = errors.New("identity: credential authority denied")

// CredentialAuthorityQuery selects exactly one credential reference under its
// tenant and user. It contains no secret or proof and grants no lookup access.
type CredentialAuthorityQuery struct {
	TenantID     TenantID
	UserID       UserID
	CredentialID CredentialID
}

// Validate checks exact bounded IDs without normalization or ownership claims.
func (q CredentialAuthorityQuery) Validate() error {
	if !validDirectoryID(string(q.TenantID)) || !validDirectoryID(string(q.UserID)) || !validDirectoryID(string(q.CredentialID)) {
		return InvalidInputError{Field: "credential_query"}
	}
	return nil
}

// CredentialAuthorityRecord is one consistent primary observation. User.Version
// is aggregate CAS; AuthorityVersion is the separate tenant/user credential
// epoch; Credential.Version belongs to the exact credential record. No two of
// these counters substitute for one another. Enabled describes only the owned
// reference's eligibility, not secret verification, factor/provider eligibility
// or authorization. ExpiresAt zero is indefinite; nonzero expiry is exclusive
// and must be a UTC-representable microsecond instant in years 1..9999.
//
// The record is data, not an opaque proof or validity lease. Its construction,
// copying and checking cannot establish read provenance or renew freshness.
// Treat it as immutable during a call; it contains no verifier or bearer.
type CredentialAuthorityRecord struct {
	User             User
	AuthorityVersion uint64
	Credential       CredentialRef
	Enabled          bool
	ExpiresAt        time.Time
}

// Format keeps scope and credential metadata out of ordinary diagnostics.
func (CredentialAuthorityRecord) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "identity.CredentialAuthorityRecord(redacted)")
}

// CredentialAuthorityRepository is the platform-owned, concurrency-safe primary
// port. Reads honor a bounded context and return the user, credential epoch and
// reference from one consistent snapshot. Missing exact user or reference is
// ErrUserAbsent; corrupt/unavailable storage is redacted Unavailable. No partial
// positive result, fallback cache, default version or caller-supplied store may
// establish authority. Mutations and proof consumption belong to their owned
// command; this interface exposes no transaction or verification material.
type CredentialAuthorityRepository interface {
	GetCredentialAuthority(context.Context, CredentialAuthorityQuery) (CredentialAuthorityRecord, error)
}

// CheckCredentialAuthority checks one expected credential against the current
// primary projection and the original user-wide credential epoch. Exact ID,
// tenant, user, kind, owner and record version must match. Blocked users and
// disabled/expired references deny even when both versions match. Ordinary user
// aggregate changes do not invalidate otherwise equal credential authority.
// Positive uint64 counters, including MaxUint64, compare without narrowing.
//
// now is the caller's one trusted decision-clock sample. This pure check performs
// no lookup, mutation, clock sampling, proof validation/consumption, issuance or
// refresh. Success cannot replace current global/tenant/user/identifier/factor/
// provider checks, verified original proof provenance or atomic finalization.
func CheckCredentialAuthority(current CredentialAuthorityRecord, expected CredentialRef, expectedAuthorityVersion uint64, now time.Time) error {
	if now.IsZero() || now.UTC().Year() < 1 || now.UTC().Year() > 9999 || expected.Validate(expected.TenantID, expected.UserID) != nil || current.User.Validate(expected.TenantID) != nil || current.User.ID != expected.UserID || !current.User.Status.AllowsAuthentication() || current.Credential.Validate(expected.TenantID, expected.UserID) != nil || current.Credential != expected || !current.Enabled || expectedAuthorityVersion == 0 || current.AuthorityVersion != expectedAuthorityVersion {
		return ErrCredentialAuthority
	}
	if !current.ExpiresAt.IsZero() && (current.ExpiresAt.UTC().Year() < 1 || current.ExpiresAt.UTC().Year() > 9999 || current.ExpiresAt.Nanosecond()%1000 != 0 || !current.ExpiresAt.After(now)) {
		return ErrCredentialAuthority
	}
	return nil
}
