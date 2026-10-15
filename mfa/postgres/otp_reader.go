package mfapostgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// OTPFactorMetadata is original confirmed-factor/recipient version custody, not
// successful OTP proof or a current authorization lease. Native send/completion
// must fence all identities/versions and original child scope in protected Work.
type OTPFactorMetadata struct {
	TenantID                                              identity.TenantID
	UserID                                                identity.UserID
	FactorID                                              string
	EnrollmentVersion, RowVersion, FactorAuthorityVersion uint64
	IdentifierID                                          identity.IdentifierID
	IdentifierVersion, VerificationVersion                uint64
	Channel                                               delivery.Channel
	ContinuationID                                        mfa.ContinuationID
	ContinuationVersion                                   uint64
	ScopeDigest                                           [32]byte
}

type otpFactorCustody struct {
	metadata  OTPFactorMetadata
	recipient kernel.RecipientRecord
}

// OTPFactorSnapshot retains immutable owned-factor/recipient custody under the
// verified original child. Copies share read-only state. It owns no resources,
// code, bearer or session authority; zero denies and diagnostics are redacted.
type OTPFactorSnapshot struct{ custody func() otpFactorCustody }

// Metadata returns an owned non-secret projection, never current factor proof.
func (s OTPFactorSnapshot) Metadata() (OTPFactorMetadata, error) {
	if s.custody == nil {
		return OTPFactorMetadata{}, invalidAuthority()
	}
	return s.custody().metadata, nil
}

// Recipient returns the original verified recipient for native encrypted
// delivery preparation only. Never expose/log its address as a client response.
// Changing the projection cannot mutate the snapshot. Protected use repeats
// exact selected identity/verification and account-security version checks.
func (s OTPFactorSnapshot) Recipient() (kernel.RecipientRecord, error) {
	if s.custody == nil {
		return kernel.RecipientRecord{}, invalidAuthority()
	}
	return s.custody().recipient, nil
}

// OTPFactorReader borrows the primary pool and current continuation reader. It
// owns no transaction/cache/background work and is safe for concurrent reads.
type OTPFactorReader struct {
	continuation *ContinuationReader
	directory    *kernel.Repository
}

// NewOTPFactorReader freezes a bounded, at most five-second shared read budget
// without IO. Missing selected OTP storage is unavailable, never known empty MFA.
func NewOTPFactorReader(pool *database.Pool, maximum time.Duration) (*OTPFactorReader, error) {
	continuation, err := NewContinuationReader(pool, maximum)
	if err != nil {
		return nil, err
	}
	directory, err := kernel.NewRepository(pool, kernel.Config{MaximumDuration: maximum})
	if err != nil {
		return nil, err
	}
	return &OTPFactorReader{continuation: continuation, directory: directory}, nil
}

// Read resolves a confirmed owned OTP factor and its exact currently verified
// recipient only under an actual live child explicitly permitting OTP. Missing,
// foreign, pending/revoked, blocked, exhausted or stale scope/recipient denies.
// This does not authenticate browser possession, verify a code, charge attempts
// or renew original primary/child time. Concurrent changes invalidate this
// snapshot; protected native use must repeat the complete fence. Earlier ctx
// deadlines win, rows close before return, and no retries are performed.
func (r *OTPFactorReader) Read(ctx context.Context, grant capability.Grant, issuer, factorID string) (OTPFactorSnapshot, error) {
	if ctx == nil || r == nil || r.continuation == nil || r.directory == nil {
		return OTPFactorSnapshot{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return OTPFactorSnapshot{}, err
	}
	if _, err := identity.ParseCommandID(factorID); err != nil {
		return OTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	ctx, stop := context.WithTimeout(ctx, r.continuation.maximumDuration)
	defer stop()
	c, err := r.continuation.Read(ctx, grant, issuer)
	if err != nil {
		return OTPFactorSnapshot{}, err
	}
	s, err := c.Bindings()
	if err != nil || !slices.Contains(s.AllowedMethods, "otp") {
		return OTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	digest, err := c.ScopeDigest()
	if err != nil {
		return OTPFactorSnapshot{}, err
	}
	var enrollment, row, identifierVersion, verificationVersion, channel, identifier, canonical string
	err = r.continuation.pool.Raw().QueryRow(ctx, `SELECT f.enrollment_version::text,f.row_version::text,f.identifier_id,f.identifier_version::text,f.verification_version::text,f.channel,i.canonical_value
FROM identity_mfa.otp_factors f
JOIN identity_mfa.factor_authorities a ON a.tenant_id=f.tenant_id AND a.user_id=f.user_id
JOIN identity_mfa.continuations c ON c.tenant_id=f.tenant_id AND c.user_id=f.user_id
JOIN identity.users u ON u.tenant_id=f.tenant_id AND u.user_id=f.user_id
JOIN identity.identifiers i ON i.tenant_id=f.tenant_id AND i.user_id=f.user_id AND i.identifier_id=f.identifier_id
WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.factor_id=$3 AND f.state=2 AND f.confirmed_at IS NOT NULL
AND u.status='active' AND a.version=$4::numeric AND a.active_factors BETWEEN 1 AND 64
AND c.continuation_id=$5 AND c.scope_digest=$6 AND c.version=$7::numeric
AND c.state IN(1,2) AND c.attempts_remaining>0 AND c.expires_at>clock_timestamp()
AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL
AND i.version=f.identifier_version AND i.verification_version=f.verification_version
AND ((f.channel='email' AND i.kind='email') OR (f.channel='sms' AND i.kind='phone'))`, string(s.TenantID), string(s.SubjectID), factorID, strconv.FormatUint(s.FactorVersion, 10), string(s.ID), digest[:], strconv.FormatUint(s.Version, 10)).Scan(&enrollment, &row, &identifier, &identifierVersion, &verificationVersion, &channel, &canonical)
	if err != nil {
		if ctx.Err() != nil {
			return OTPFactorSnapshot{}, ctx.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return OTPFactorSnapshot{}, identity.ForbiddenError{}
		}
		return OTPFactorSnapshot{}, identity.UnavailableError{}
	}
	metadata := OTPFactorMetadata{TenantID: s.TenantID, UserID: identity.UserID(s.SubjectID), FactorID: factorID, FactorAuthorityVersion: s.FactorVersion, IdentifierID: identity.IdentifierID(identifier), ContinuationID: s.ID, ContinuationVersion: s.Version, ScopeDigest: digest, Channel: delivery.ChannelEmail}
	if channel == "sms" {
		metadata.Channel = delivery.ChannelSMS
	} else if channel != "email" {
		return OTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	for i, text := range []string{enrollment, row, identifierVersion, verificationVersion} {
		value, err := strconv.ParseUint(text, 10, 64)
		if err != nil || value == 0 {
			return OTPFactorSnapshot{}, identity.ForbiddenError{}
		}
		switch i {
		case 0:
			metadata.EnrollmentVersion = value
		case 1:
			metadata.RowVersion = value
		case 2:
			metadata.IdentifierVersion = value
		case 3:
			metadata.VerificationVersion = value
		}
	}
	kind := identity.IdentifierEmail
	if metadata.Channel == delivery.ChannelSMS {
		kind = identity.IdentifierPhone
	}
	recipient, err := r.directory.ResolveRecipient(ctx, kernel.RecipientQuery{TenantID: s.TenantID, UserID: metadata.UserID, Kind: kind, CanonicalValue: canonical, Eligibility: kernel.RecipientVerified})
	if err != nil || recipient.Suppressed || recipient.Identifier.ID != metadata.IdentifierID || recipient.Identifier.Version != metadata.IdentifierVersion || recipient.Verification.Version != metadata.VerificationVersion {
		if err != nil {
			return OTPFactorSnapshot{}, err
		}
		return OTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	state := otpFactorCustody{metadata: metadata, recipient: recipient}
	return OTPFactorSnapshot{custody: func() otpFactorCustody { return state }}, ctx.Err()
}

// Format redacts correlated factor/recipient metadata.
func (OTPFactorMetadata) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPFactorMetadata(redacted)"))
}

// MarshalJSON rejects implicit metadata export.
func (OTPFactorMetadata) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit metadata export.
func (OTPFactorMetadata) MarshalText() ([]byte, error) { return nil, invalidAuthority() }

// Format redacts original factor/recipient custody.
func (OTPFactorSnapshot) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.OTPFactorSnapshot(redacted)"))
}

// MarshalJSON rejects snapshot export.
func (OTPFactorSnapshot) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects snapshot export.
func (OTPFactorSnapshot) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
