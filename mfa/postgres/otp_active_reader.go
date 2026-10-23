package mfapostgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// OTPActiveFactorMetadata preserves a confirmed factor, recipient versions and
// the real session owner's original observation deadline. Factor's login-child
// fields remain zero: this profile does not reinterpret a completed/expired
// login continuation as current authority. No metadata grants factor proof.
type OTPActiveFactorMetadata struct {
	Factor         OTPFactorMetadata
	SessionID      string
	SessionVersion uint64
	ValidUntil     time.Time
}

// OTPActiveFactorSnapshot is immutable active-factor/verified-recipient custody
// for authenticated step-up, distinct from pending enrollment and partial login.
// It contains no generated/submitted code and owns no resources. Copies cannot
// renew the original session observation. Native use must repeat current fences.
type OTPActiveFactorSnapshot struct{ custody func() otpActiveFactorCustody }

type otpActiveFactorCustody struct {
	metadata  OTPActiveFactorMetadata
	recipient kernel.RecipientRecord
}

// Metadata returns original scalar custody, not a fresh authorization lease.
func (s OTPActiveFactorSnapshot) Metadata() (OTPActiveFactorMetadata, error) {
	if s.custody == nil {
		return OTPActiveFactorMetadata{}, invalidAuthority()
	}
	return s.custody().metadata, nil
}

// Recipient returns the exact verified destination only for native encrypted
// delivery preparation. It must not be included in responses or diagnostics.
func (s OTPActiveFactorSnapshot) Recipient() (kernel.RecipientRecord, error) {
	if s.custody == nil {
		return kernel.RecipientRecord{}, invalidAuthority()
	}
	return s.custody().recipient, nil
}

// ReadForStepUp reads a confirmed owned email OTP factor under a real current
// SessionService.Get result obtained by the configured native adapter. A caller
// projection or Authenticated flag cannot replace its private observation.
// This performs bounded primary reads, not code comparison, permission, risk
// admission or mutation. Final use must fence the same factor, recipient,
// session and primary owners together after waits in the sole protected Work.
// Unsupported SMS, missing/changed/foreign state and expired observations deny;
// outages and corrupt storage fail closed. Borrowed pool lifetime is unchanged.
func (r *OTPFactorReader) ReadForStepUp(ctx context.Context, original session.GetResult, factorID string) (OTPActiveFactorSnapshot, error) {
	zero := OTPActiveFactorSnapshot{}
	if ctx == nil || r == nil || r.continuation == nil || r.directory == nil || r.continuation.pool == nil || r.continuation.pool.Raw() == nil {
		return zero, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	if _, err := identity.ParseCommandID(factorID); err != nil || original.ValidateAt(time.Now()) != nil {
		return zero, identity.ForbiddenError{}
	}
	spec, err := original.Session.Bindings()
	if err != nil || spec.Authentication.Kind == session.AuthenticationAnonymous {
		return zero, identity.ForbiddenError{}
	}
	bounded, stop := context.WithTimeout(ctx, r.continuation.maximumDuration)
	defer stop()
	var enrollment, row, authority, identifier, iv, vv, destination string
	err = r.continuation.pool.Raw().QueryRow(bounded, `SELECT f.enrollment_version::text,f.row_version::text,a.version::text,
f.identifier_id,f.identifier_version::text,f.verification_version::text,i.canonical_value
FROM identity_mfa.otp_factors f
JOIN identity_mfa.factor_authorities a ON a.tenant_id=f.tenant_id AND a.user_id=f.user_id
JOIN identity.users u ON u.tenant_id=f.tenant_id AND u.user_id=f.user_id
JOIN identity.identifiers i ON i.tenant_id=f.tenant_id AND i.user_id=f.user_id AND i.identifier_id=f.identifier_id
WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.factor_id=$3 AND f.state=2 AND f.confirmed_at IS NOT NULL
AND f.channel='email' AND a.active_factors BETWEEN 1 AND 64 AND u.status='active'
AND i.kind='email' AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL
AND i.version=f.identifier_version AND i.verification_version=f.verification_version`, string(spec.TenantID), string(spec.UserID), factorID).Scan(&enrollment, &row, &authority, &identifier, &iv, &vv, &destination)
	if bounded.Err() != nil {
		return zero, bounded.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, identity.ForbiddenError{}
	}
	if err != nil {
		return zero, identity.UnavailableError{}
	}
	metadata := OTPFactorMetadata{TenantID: spec.TenantID, UserID: spec.UserID, FactorID: factorID, IdentifierID: identity.IdentifierID(identifier), Channel: delivery.ChannelEmail}
	values := []*uint64{&metadata.EnrollmentVersion, &metadata.RowVersion, &metadata.FactorAuthorityVersion, &metadata.IdentifierVersion, &metadata.VerificationVersion}
	for i, text := range []string{enrollment, row, authority, iv, vv} {
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != text {
			return zero, identity.UnavailableError{}
		}
		*values[i] = value
	}
	recipient, err := r.directory.ResolveRecipient(bounded, kernel.RecipientQuery{TenantID: spec.TenantID, UserID: spec.UserID, Kind: identity.IdentifierEmail, CanonicalValue: destination, Eligibility: kernel.RecipientVerified})
	if err != nil {
		return zero, err
	}
	if recipient.Suppressed || recipient.Identifier.ID != metadata.IdentifierID || recipient.Identifier.Version != metadata.IdentifierVersion || recipient.Verification.Version != metadata.VerificationVersion || original.ValidateAt(time.Now()) != nil {
		return zero, identity.ForbiddenError{}
	}
	if err := bounded.Err(); err != nil {
		return zero, err
	}
	owned := otpActiveFactorCustody{metadata: OTPActiveFactorMetadata{Factor: metadata, SessionID: spec.SessionID, SessionVersion: spec.Version, ValidUntil: original.ValidUntil()}, recipient: recipient}
	return OTPActiveFactorSnapshot{custody: func() otpActiveFactorCustody { return owned }}, nil
}

// Format prevents diagnostic traversal of correlated factor/session metadata.
func (OTPActiveFactorMetadata) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPActiveFactorMetadata(redacted)"))
}

// MarshalJSON rejects implicit custody export.
func (OTPActiveFactorMetadata) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit custody export.
func (OTPActiveFactorMetadata) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// Format prevents diagnostic traversal of recipient or original custody.
func (OTPActiveFactorSnapshot) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPActiveFactorSnapshot(redacted)"))
}

// MarshalJSON rejects implicit custody export.
func (OTPActiveFactorSnapshot) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit custody export.
func (OTPActiveFactorSnapshot) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
