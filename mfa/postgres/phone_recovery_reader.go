package mfapostgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/jackc/pgx/v5"
)

// ReadForPhoneRecovery reads one confirmed encrypted factor without inventing a
// login continuation or authenticated session. Tenant/user/factor select only
// structural custody, never recovery authorization. The native phone owner must
// authenticate the original reset capability and all phone/pre-auth/risk and
// password authority, then match its original factor generations. Missing,
// inactive, foreign or corrupt state denies. The shared reader budget bounds IO;
// no secret is decrypted, attempt charged or replay advanced here.
func (r *TOTPFactorReader) ReadForPhoneRecovery(ctx context.Context, tenant identity.TenantID, user identity.UserID, factorID string) (TOTPFactorSnapshot, error) {
	if ctx == nil || r == nil || r.continuation == nil || r.continuation.pool == nil || r.continuation.pool.Raw() == nil {
		return TOTPFactorSnapshot{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return TOTPFactorSnapshot{}, err
	}
	for _, id := range []string{string(tenant), string(user)} {
		if _, err := identity.ParseIdentifierID(id); err != nil {
			return TOTPFactorSnapshot{}, invalidAuthority()
		}
	}
	if _, err := identity.ParseCommandID(factorID); err != nil {
		return TOTPFactorSnapshot{}, invalidAuthority()
	}
	bounded, cancel := context.WithTimeout(ctx, r.continuation.maximumDuration)
	defer cancel()
	var wire []byte
	var enrollment, row, authority string
	var last *string
	var algorithm, issuer string
	var digits, period, skew int16
	err := r.continuation.pool.Raw().QueryRow(bounded, `SELECT
CASE WHEN octet_length(t.encrypted_secret) BETWEEN 1 AND 4096 THEN t.encrypted_secret END,
t.enrollment_version::text,t.row_version::text,a.version::text,t.last_step::text,
t.algorithm,t.digits,t.period_seconds,t.skew_steps,t.issuer
FROM identity_mfa.totp_factors t
JOIN identity_mfa.factor_authorities a ON a.tenant_id=t.tenant_id AND a.user_id=t.user_id
JOIN identity.users u ON u.tenant_id=t.tenant_id AND u.user_id=t.user_id
WHERE t.tenant_id=$1 AND t.user_id=$2 AND t.factor_id=$3 AND t.state=2
AND t.confirmed_at IS NOT NULL AND t.encrypted_secret IS NOT NULL
AND a.active_factors BETWEEN 1 AND 64 AND u.status='active'`, string(tenant), string(user), factorID).Scan(&wire, &enrollment, &row, &authority, &last, &algorithm, &digits, &period, &skew, &issuer)
	defer clear(wire)
	if bounded.Err() != nil {
		return TOTPFactorSnapshot{}, bounded.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return TOTPFactorSnapshot{}, identity.ForbiddenError{}
	}
	if err != nil {
		return TOTPFactorSnapshot{}, identity.UnavailableError{}
	}
	m := TOTPFactorMetadata{TenantID: tenant, UserID: user, FactorID: factorID, Profile: mfa.TOTPProfile{Algorithm: algorithm, Digits: uint32(digits), Period: time.Duration(period) * time.Second, AllowedSkewSteps: uint32(skew), Issuer: issuer}}
	var ee, re, ae error
	m.EnrollmentVersion, ee = strconv.ParseUint(enrollment, 10, 64)
	m.RowVersion, re = strconv.ParseUint(row, 10, 64)
	m.FactorAuthorityVersion, ae = strconv.ParseUint(authority, 10, 64)
	if ee != nil || re != nil || ae != nil || m.EnrollmentVersion == 0 || m.RowVersion == 0 || m.FactorAuthorityVersion == 0 || digits < 0 || period < 0 || skew < 0 || m.Profile.Validate() != nil || len(wire) == 0 || len(wire) > 4096 {
		return TOTPFactorSnapshot{}, identity.UnavailableError{}
	}
	if last != nil {
		m.Replay.Used = true
		m.Replay.LastStep, err = strconv.ParseUint(*last, 10, 64)
		if err != nil {
			return TOTPFactorSnapshot{}, identity.UnavailableError{}
		}
	}
	binding, err := totpEncryptionContext(tenant, user, factorID, m.EnrollmentVersion, m.Profile)
	if err != nil {
		return TOTPFactorSnapshot{}, err
	}
	if _, err := envelope.ParseEnvelope(wire); err != nil {
		return TOTPFactorSnapshot{}, identity.UnavailableError{}
	}
	if err := bounded.Err(); err != nil {
		return TOTPFactorSnapshot{}, err
	}
	owned := totpFactorCustody{metadata: m, wire: append([]byte(nil), wire...), binding: binding}
	return TOTPFactorSnapshot{custody: func() totpFactorCustody { return owned }}, nil
}
