package mfapostgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope"
	"github.com/jackc/pgx/v5"
)

// TOTPActiveFactorMetadata preserves the confirmed factor fence and original
// authenticated session observation. ValidUntil is that observation's exclusive
// deadline, not a fresh factor lease. Neither metadata nor a matching TOTP
// counter is step-up proof; native protected issuance must recheck all owners.
type TOTPActiveFactorMetadata struct {
	Factor         TOTPFactorMetadata
	SessionID      string
	SessionVersion uint64
	ValidUntil     time.Time
}

// TOTPActiveFactorSnapshot is encrypted active-factor custody for authenticated
// step-up, not anonymous login or pending enrollment. It cannot be converted to
// their snapshot types. Copies retain immutable ciphertext; plaintext belongs
// to the native service to decrypt outside locks and clear after verification.
type TOTPActiveFactorSnapshot struct {
	custody func() activeTOTPFactorCustody
}
type activeTOTPFactorCustody struct {
	metadata TOTPActiveFactorMetadata
	factor   TOTPFactorSnapshot
}

// Metadata returns independently owned scalar/profile data without renewing
// original session validity or asserting that verification committed.
func (s TOTPActiveFactorSnapshot) Metadata() (TOTPActiveFactorMetadata, error) {
	if s.custody == nil {
		return TOTPActiveFactorMetadata{}, invalidAuthority()
	}
	return s.custody().metadata, nil
}

// Envelope returns a freshly parsed encrypted factor, never plaintext.
func (s TOTPActiveFactorSnapshot) Envelope() (envelope.Envelope, error) {
	if s.custody == nil {
		return envelope.Envelope{}, invalidAuthority()
	}
	return s.custody().factor.Envelope()
}

// EncryptionContext retains the unchanged existing factor-envelope binding.
func (s TOTPActiveFactorSnapshot) EncryptionContext() (envelope.Context, error) {
	if s.custody == nil {
		return envelope.Context{}, invalidAuthority()
	}
	return s.custody().factor.EncryptionContext()
}

// ReadForStepUp reads confirmed encrypted factor custody for the exact subject
// of an owned current SessionService.Get result. The native composition must
// obtain that result from its configured real session adapter using the actual
// submitted token and enforce action policy before calling. A client-supplied
// Authenticated flag or Session value cannot replace its private custody.
//
// This reads no code, grants no step-up authority and performs no mutation. It
// preserves the original observation deadline across the bounded primary read.
// Final protected execution still requires original bearer/CSRF possession,
// current primary/factor authority, exact encrypted-factor fence and replay
// advancement with actual code verification. Missing/unsupported state denies;
// unavailable/corrupt storage fails closed. Borrowed pool ownership is unchanged.
func (r *TOTPFactorReader) ReadForStepUp(ctx context.Context, original session.GetResult, factorID string) (TOTPActiveFactorSnapshot, error) {
	zero := TOTPActiveFactorSnapshot{}
	if ctx == nil || r == nil || r.continuation == nil || r.continuation.pool == nil || r.continuation.pool.Raw() == nil {
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
	var wire []byte
	var enrollment, row, authority string
	var last *string
	var algorithm, issuer string
	var digits, period, skew int16
	err = r.continuation.pool.Raw().QueryRow(bounded, `SELECT
CASE WHEN octet_length(t.encrypted_secret) BETWEEN 1 AND 4096 THEN t.encrypted_secret END,
t.enrollment_version::text,t.row_version::text,a.version::text,t.last_step::text,
t.algorithm,t.digits,t.period_seconds,t.skew_steps,t.issuer
FROM identity_mfa.totp_factors t
JOIN identity_mfa.factor_authorities a ON a.tenant_id=t.tenant_id AND a.user_id=t.user_id
JOIN identity.users u ON u.tenant_id=t.tenant_id AND u.user_id=t.user_id
WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3 AND t.state=2
AND t.confirmed_at IS NOT NULL AND t.encrypted_secret IS NOT NULL
AND a.active_factors BETWEEN 1 AND 64 AND u.status='active'`, string(spec.TenantID), string(spec.UserID), factorID).Scan(&wire, &enrollment, &row, &authority, &last, &algorithm, &digits, &period, &skew, &issuer)
	defer clear(wire)
	if bounded.Err() != nil {
		return zero, bounded.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, identity.ForbiddenError{}
	}
	if err != nil {
		return zero, identity.UnavailableError{}
	}
	if len(wire) == 0 || len(wire) > 4096 || digits < 0 || period < 0 || skew < 0 {
		return zero, identity.UnavailableError{}
	}
	profile := mfa.TOTPProfile{Algorithm: algorithm, Digits: uint32(digits), Period: time.Duration(period) * time.Second, AllowedSkewSteps: uint32(skew), Issuer: issuer}
	ev, ee := strconv.ParseUint(enrollment, 10, 64)
	rv, re := strconv.ParseUint(row, 10, 64)
	av, ae := strconv.ParseUint(authority, 10, 64)
	if ee != nil || re != nil || ae != nil || ev == 0 || rv == 0 || av == 0 || profile.Validate() != nil {
		return zero, identity.UnavailableError{}
	}
	replay := mfa.TOTPReplayState{}
	if last != nil {
		replay.Used = true
		replay.LastStep, err = strconv.ParseUint(*last, 10, 64)
		if err != nil {
			return zero, identity.UnavailableError{}
		}
	}
	binding, err := totpEncryptionContext(spec.TenantID, spec.UserID, factorID, ev, profile)
	if err != nil {
		return zero, err
	}
	if _, err := envelope.ParseEnvelope(wire); err != nil || original.ValidateAt(time.Now()) != nil {
		return zero, identity.ForbiddenError{}
	}
	if err := bounded.Err(); err != nil {
		return zero, err
	}
	meta := TOTPFactorMetadata{TenantID: spec.TenantID, UserID: spec.UserID, FactorID: factorID, EnrollmentVersion: ev, RowVersion: rv, FactorAuthorityVersion: av, Profile: profile, Replay: replay}
	factor := totpFactorCustody{metadata: meta, wire: append([]byte(nil), wire...), binding: binding}
	owned := activeTOTPFactorCustody{metadata: TOTPActiveFactorMetadata{Factor: meta, SessionID: spec.SessionID, SessionVersion: spec.Version, ValidUntil: original.ValidUntil()}, factor: TOTPFactorSnapshot{custody: func() totpFactorCustody { return factor }}}
	return TOTPActiveFactorSnapshot{custody: func() activeTOTPFactorCustody { return owned }}, nil
}

// Format redacts ciphertext and correlated source/factor metadata.
func (TOTPActiveFactorSnapshot) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("mfapostgres.TOTPActiveFactorSnapshot(redacted)"))
}

// MarshalJSON rejects implicit custody export.
func (TOTPActiveFactorSnapshot) MarshalJSON() ([]byte, error) { return nil, invalidAuthority() }

// MarshalText rejects implicit custody export.
func (TOTPActiveFactorSnapshot) MarshalText() ([]byte, error) { return nil, invalidAuthority() }
