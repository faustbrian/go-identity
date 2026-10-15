package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	database "github.com/faustbrian/go-postgres"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/jackc/pgx/v5"
)

// TOTPFactorMetadata is a trusted reader's non-secret version fence. It is not
// factor proof or session permission. Native completion must recheck all these
// identities/versions and atomically advance Replay in the protected Work.
type TOTPFactorMetadata struct {
	TenantID                                              identity.TenantID
	UserID                                                identity.UserID
	FactorID                                              string
	EnrollmentVersion, RowVersion, FactorAuthorityVersion uint64
	ContinuationID                                        mfa.ContinuationID
	ContinuationVersion                                   uint64
	ScopeDigest                                           [32]byte
	Profile                                               mfa.TOTPProfile
	Replay                                                mfa.TOTPReplayState
}

type totpFactorCustody struct {
	metadata TOTPFactorMetadata
	wire     []byte
	binding  envelope.Context
}

// TOTPFactorSnapshot retains immutable encrypted custody behind an opaque
// closure; diagnostics cannot traverse ciphertext or account metadata. Zero
// denies. Copies share immutable custody and concurrent reads are safe. It
// carries no plaintext and cannot authenticate or consume a continuation.
type TOTPFactorSnapshot struct{ custody func() totpFactorCustody }

// Metadata returns an owned scalar profile/version projection. A populated
// value is not proof of current storage authority or successful verification.
func (s TOTPFactorSnapshot) Metadata() (TOTPFactorMetadata, error) {
	if s.custody == nil {
		return TOTPFactorMetadata{}, invalidAuthority()
	}
	return s.custody().metadata, nil
}

// Envelope returns a fresh immutable encrypted envelope and never decrypts it.
// The consuming MFA service owns bounded secret-envelope decryption and must
// clear plaintext and destroy its opaque password.Secret after computation.
func (s TOTPFactorSnapshot) Envelope() (envelope.Envelope, error) {
	if s.custody == nil {
		return envelope.Envelope{}, invalidAuthority()
	}
	sealed, err := envelope.ParseEnvelope(s.custody().wire)
	if err != nil {
		return envelope.Envelope{}, identity.UnavailableError{}
	}
	return sealed, nil
}

// EncryptionContext returns the exact authenticated tenant/user/factor/
// enrollment/profile binding, unchanged across wrapping-key rotation.
func (s TOTPFactorSnapshot) EncryptionContext() (envelope.Context, error) {
	if s.custody == nil {
		return envelope.Context{}, invalidAuthority()
	}
	return s.custody().binding, nil
}

// TOTPFactorReader borrows primary PostgreSQL and owns no transaction, cache,
// goroutine or pool lifetime. Concurrent reads are safe. It reveals encrypted
// custody only for a verified, live child continuation permitting TOTP.
type TOTPFactorReader struct{ continuation *ContinuationReader }

// NewTOTPFactorReader configures one shared read budget, at most five seconds;
// earlier caller deadlines win. It performs no IO.
func NewTOTPFactorReader(pool *database.Pool, maximumDuration time.Duration) (*TOTPFactorReader, error) {
	reader, err := NewContinuationReader(pool, maximumDuration)
	if err != nil {
		return nil, err
	}
	return &TOTPFactorReader{continuation: reader}, nil
}

// Read restores confirmed, encrypted TOTP custody under original continuation
// scope and current primary authority. It never verifies a code, spends an
// attempt, advances replay or grants session issuance. Concurrent changes may
// invalidate the snapshot: final protected execution must recheck its complete
// fence. Missing, foreign, pending, revoked or stale state denies; unavailable
// storage fails closed. No plaintext, unbounded read, renewal or retry occurs.
func (r *TOTPFactorReader) Read(ctx context.Context, grant capability.Grant, issuer, factorID string) (TOTPFactorSnapshot, error) {
	if ctx == nil || r == nil || r.continuation == nil {
		return TOTPFactorSnapshot{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return TOTPFactorSnapshot{}, err
	}
	if _, err := identity.ParseCommandID(factorID); err != nil {
		return TOTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	bounded, cancel := context.WithTimeout(ctx, r.continuation.maximumDuration)
	defer cancel()
	c, err := r.continuation.Read(bounded, grant, issuer)
	if err != nil {
		return TOTPFactorSnapshot{}, err
	}
	s, err := c.Bindings()
	if err != nil || !slices.Contains(s.AllowedMethods, "totp") {
		return TOTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	digest, err := c.ScopeDigest()
	if err != nil {
		return TOTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	var wire []byte
	var enrollmentVersion, rowVersion string
	var last *string
	var algorithm, profileIssuer string
	var digits, period, skew int16
	err = r.continuation.pool.Raw().QueryRow(bounded, `SELECT t.encrypted_secret,t.enrollment_version::text,t.row_version::text,t.last_step::text,t.algorithm,t.digits,t.period_seconds,t.skew_steps,t.issuer
FROM identity_mfa.totp_factors t
JOIN identity_mfa.factor_authorities a ON a.tenant_id=t.tenant_id AND a.user_id=t.user_id
JOIN identity_mfa.continuations c ON c.tenant_id=t.tenant_id AND c.user_id=t.user_id
JOIN identity.users u ON u.tenant_id=t.tenant_id AND u.user_id=t.user_id
WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3 AND t.state=2
AND t.confirmed_at IS NOT NULL AND t.encrypted_secret IS NOT NULL AND u.status='active'
AND a.version=$4::numeric AND a.active_factors BETWEEN 1 AND 64
AND c.continuation_id=$5 AND c.scope_digest=$6 AND c.version=$7::numeric
AND c.state IN(1,2) AND c.attempts_remaining>0 AND c.expires_at>clock_timestamp()`, string(s.TenantID), string(s.SubjectID), factorID, strconv.FormatUint(s.FactorVersion, 10), string(s.ID), digest[:], strconv.FormatUint(s.Version, 10)).Scan(&wire, &enrollmentVersion, &rowVersion, &last, &algorithm, &digits, &period, &skew, &profileIssuer)
	defer clear(wire)
	if err != nil {
		if bounded.Err() != nil {
			return TOTPFactorSnapshot{}, bounded.Err()
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return TOTPFactorSnapshot{}, identity.ForbiddenError{}
		}
		return TOTPFactorSnapshot{}, identity.UnavailableError{}
	}
	if len(wire) == 0 || len(wire) > 4096 || digits < 0 || period < 0 || skew < 0 {
		return TOTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	profile := mfa.TOTPProfile{Algorithm: algorithm, Digits: uint32(digits), Period: time.Duration(period) * time.Second, AllowedSkewSteps: uint32(skew), Issuer: profileIssuer}
	if profile.Validate() != nil {
		return TOTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	ev, e := strconv.ParseUint(enrollmentVersion, 10, 64)
	rv, re := strconv.ParseUint(rowVersion, 10, 64)
	if e != nil || re != nil || ev == 0 || rv == 0 {
		return TOTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	replay := mfa.TOTPReplayState{}
	if last != nil {
		replay.Used = true
		replay.LastStep, err = strconv.ParseUint(*last, 10, 64)
		if err != nil {
			return TOTPFactorSnapshot{}, identity.ForbiddenError{}
		}
	}
	binding, err := totpEncryptionContext(s.TenantID, identity.UserID(s.SubjectID), factorID, ev, profile)
	if err != nil {
		return TOTPFactorSnapshot{}, err
	}
	if _, err := envelope.ParseEnvelope(wire); err != nil {
		return TOTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	if err := bounded.Err(); err != nil {
		return TOTPFactorSnapshot{}, err
	}
	owned := totpFactorCustody{metadata: TOTPFactorMetadata{TenantID: s.TenantID, UserID: identity.UserID(s.SubjectID), FactorID: factorID, EnrollmentVersion: ev, RowVersion: rv, FactorAuthorityVersion: s.FactorVersion, ContinuationID: s.ID, ContinuationVersion: s.Version, ScopeDigest: digest, Profile: profile, Replay: replay}, wire: append([]byte(nil), wire...), binding: binding}
	return TOTPFactorSnapshot{custody: func() totpFactorCustody { return owned }}, nil
}

// This persistence encoding is fixed independently of future public profile
// additions. Changing it requires a distinct envelope-context profile, not
// silently making existing encrypted factors undecryptable.
type totpEnvelopeProfileV1 struct {
	Algorithm     string
	Digits        uint32
	PeriodSeconds int64
	SkewSteps     uint32
	Issuer        string
}

func totpEncryptionContext(tenant identity.TenantID, user identity.UserID, factor string, version uint64, profile mfa.TOTPProfile) (envelope.Context, error) {
	if profile.Validate() != nil || version == 0 {
		return envelope.Context{}, invalidAuthority()
	}
	bytes, err := json.Marshal(totpEnvelopeProfileV1{Algorithm: profile.Algorithm, Digits: profile.Digits, PeriodSeconds: int64(profile.Period / time.Second), SkewSteps: profile.AllowedSkewSteps, Issuer: profile.Issuer})
	if err != nil {
		return envelope.Context{}, invalidAuthority()
	}
	digest := sha256.Sum256(bytes)
	binding, err := envelope.NewContext(map[string]string{"service": "identity.mfa", "field": "totp-secret-v1", "tenant": string(tenant), "user": string(user), "factor": factor, "enrollment_version": strconv.FormatUint(version, 10), "profile": hex.EncodeToString(digest[:])})
	if err != nil {
		return envelope.Context{}, invalidAuthority()
	}
	return binding, nil
}
