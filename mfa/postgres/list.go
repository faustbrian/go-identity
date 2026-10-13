package mfapostgres

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	"github.com/jackc/pgx/v5"
)

// TOTPListReader borrows the existing TOTP-only enrollment owner and primary
// pool. That profile explicitly does not issue trusted devices or security-key
// factors. An unexpected active-factor count denies instead of omitting another
// owner's state. Empty trusted-device output describes this selected profile,
// not a claim that unsupported device storage is an authoritative empty store.
// No secret, envelope, verifier, replay counter or credential is selected.
// This structural reader is not an authentication or enumeration endpoint.
type TOTPListReader struct{ shared *totpEnrollmentState }

// NewTOTPListReader selects the existing native TOTP metadata profile without
// IO. Enrollment supplies the immutable whole-read bound and primary owner;
// callers must keep it and its pool alive until all reads finish. This does not
// select a route, initialize missing authority or grant access to another user.
func NewTOTPListReader(enrollment *TOTPEnrollmentService) (*TOTPListReader, error) {
	if enrollment == nil || enrollment.state == nil {
		return nil, invalidAuthority()
	}
	s := enrollment.state()
	if s == nil || s.pool == nil || s.pool.Raw() == nil || s.config.MaximumDuration < time.Millisecond || s.config.MaximumDuration > 5*time.Second {
		return nil, invalidAuthority()
	}
	return &TOTPListReader{shared: s}, nil
}

// ReadFactors reads one bounded, coherent primary snapshot of safe TOTP metadata
// and unused active-set recovery counts. It has no mutations, private transaction
// or retries. The outer service authenticates/authorizes and rechecks its original
// session before disclosure. Missing subject/authority denies; corrupt, oversized
// or unsupported inventories and outages return no partial data. Consumed codes,
// pending/retired sets and revoked factors never contribute remaining counts.
func (r *TOTPListReader) ReadFactors(ctx context.Context, q mfa.FactorListQuery) (mfa.FactorListSnapshot, error) {
	zero := mfa.FactorListSnapshot{}
	if ctx == nil || r == nil || r.shared == nil || r.shared.pool == nil || r.shared.pool.Raw() == nil {
		return zero, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(q.TenantID)); err != nil {
		return zero, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(q.UserID)); err != nil {
		return zero, invalidAuthority()
	}
	bounded, stop := context.WithTimeout(ctx, r.shared.config.MaximumDuration)
	defer stop()
	if bounded.Err() != nil {
		return zero, bounded.Err()
	}
	var version string
	var active int32
	var remaining, sets, badSets, distinctFactors int64
	var wire []byte
	var observed time.Time
	err := r.shared.pool.Raw().QueryRow(bounded, factorListSQL, string(q.TenantID), string(q.UserID)).Scan(&version, &active, &observed, &wire, &remaining, &sets, &badSets, &distinctFactors)
	if bounded.Err() != nil {
		return zero, bounded.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, identity.ForbiddenError{}
	}
	if err != nil {
		return zero, identity.UnavailableError{}
	}
	if len(wire) < 2 || len(wire) > 65536 || active < 0 || active > 64 || remaining < 0 || remaining > 100 || sets < 0 || sets > 64 || badSets != 0 || distinctFactors != sets {
		return zero, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || v == 0 {
		return zero, identity.UnavailableError{}
	}
	var factors []mfa.FactorProjection
	if json.Unmarshal(wire, &factors) != nil || len(factors) > 100 {
		return zero, identity.UnavailableError{}
	}
	var confirmed int32
	for _, f := range factors {
		if f.State == mfa.FactorActive {
			confirmed++
		}
	}
	if confirmed != active {
		return zero, identity.UnavailableError{}
	}
	snapshot := mfa.FactorListSnapshot{TenantID: q.TenantID, UserID: q.UserID, AuthorityVersion: v, Factors: factors, TrustedDevices: []mfa.TrustedDeviceProjection{}, RecoveryCodeCount: uint32(remaining)}
	if _, err := snapshot.Projection(q, observed); err != nil {
		return zero, err
	}
	if bounded.Err() != nil {
		return zero, bounded.Err()
	}
	return snapshot, nil
}

// The LIMITs bound row materialization before JSON allocation. Recovery sets use
// their existing native state/version interpretation: initial enrollment's set
// epoch is not the global factor generation, so equality would hide valid codes.
// Every retained active set must have exactly its declared contiguous code rows.
const factorListSQL = `WITH scope AS (
 SELECT a.tenant_id,a.user_id,a.version,a.active_factors,statement_timestamp() AS observed
 FROM identity_mfa.factor_authorities a JOIN identity.users u USING(tenant_id,user_id)
 WHERE a.tenant_id=$1 AND a.user_id=$2 AND u.status='active'
), factors AS (
 SELECT t.factor_id,t.state,t.created_at,t.row_version
 FROM identity_mfa.totp_factors t JOIN scope s USING(tenant_id,user_id)
 WHERE t.state<>1 OR t.enrollment_expires_at>s.observed
 ORDER BY t.factor_id LIMIT 101
), factor_json AS (
 SELECT COALESCE(jsonb_agg(jsonb_build_object('ID',factor_id,'Method','totp','State',state,
 'CreatedAt',created_at,'Version',row_version) ORDER BY factor_id),'[]'::jsonb) AS value
 FROM factors
), active_sets AS (
 SELECT r.tenant_id,r.set_id,r.factor_id,r.code_count
 FROM identity_mfa.recovery_sets r
 JOIN scope s USING(tenant_id,user_id)
 JOIN identity_mfa.totp_factors t USING(tenant_id,user_id,factor_id)
 WHERE r.state=2 AND t.state=2 AND t.confirmed_at IS NOT NULL
 ORDER BY r.set_id LIMIT 65
), code_counts AS (
 SELECT r.set_id,r.factor_id,r.code_count,count(c.code_index) AS actual,
 min(c.code_index) AS first,max(c.code_index) AS last,
 count(c.code_index) FILTER(WHERE c.consumed_at IS NULL) AS remaining
 FROM active_sets r LEFT JOIN identity_mfa.recovery_codes c USING(tenant_id,set_id)
 GROUP BY r.set_id,r.factor_id,r.code_count
), recovery AS (
 SELECT COALESCE(sum(remaining),0)::bigint AS remaining,count(*) AS sets,
 count(*) FILTER(WHERE actual<>code_count OR first<>0 OR last<>code_count-1) AS bad,
 count(DISTINCT factor_id) AS factors FROM code_counts
)
SELECT s.version::text,s.active_factors,s.observed,
 CASE WHEN octet_length(j.value::text)<=65536 THEN j.value::text END,
 r.remaining,r.sets,r.bad,r.factors
FROM scope s CROSS JOIN factor_json j CROSS JOIN recovery r`
