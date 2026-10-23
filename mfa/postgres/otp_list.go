package mfapostgres

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

// OTPListReader reads safe native TOTP/OTP metadata from one coherent primary
// snapshot. The OTP enrollment history includes both factor owners. It grants
// no authentication, mutation or permission to omit another active method;
// unsupported inventories fail the shared aggregate-count check. It owns no
// pool, transaction, cache or goroutine and is safe for concurrent calls.
type OTPListReader struct{ native *TOTPListReader }

// NewOTPListReader borrows the actual native OTP enrollment owner without IO.
// Install its selected shared TOTP/OTP histories first. The caller authenticates
// and authorizes the subject and must recheck original validity after reading.
// Labels remain empty unless management metadata is explicitly selected.
func NewOTPListReader(enrollment *OTPEnrollmentService) (*OTPListReader, error) {
	if enrollment == nil || enrollment.engine == nil || enrollment.engine.state == nil {
		return nil, invalidAuthority()
	}
	native, err := newTOTPListReader(enrollment.engine.state(), otpFactorListSQL)
	if err != nil {
		return nil, err
	}
	return &OTPListReader{native: native}, nil
}

// NewOTPManagementListReader additionally selects the existing TOTP owner's
// managed labels, without requiring or inventing OTP label storage. Both owners
// must borrow the same primary pool. The earlier whole-read budget wins.
func NewOTPManagementListReader(enrollment *OTPEnrollmentService, management *FactorUpdateService) (*OTPListReader, error) {
	r, err := NewOTPListReader(enrollment)
	if err != nil || management == nil || management.state == nil {
		return nil, invalidAuthority()
	}
	m := management.state()
	if m == nil || m.shared == nil || m.shared.pool != r.native.shared.pool {
		return nil, invalidAuthority()
	}
	// Only this constructor selects the separately installed management column.
	// The base reader must still work against the original enrollment schema.
	r.native.query = strings.Replace(otpFactorListSQL, "''::text AS label", "t.label AS label", 1)
	if m.shared.config.MaximumDuration < r.native.shared.config.MaximumDuration {
		shared := *r.native.shared
		shared.config.MaximumDuration = m.shared.config.MaximumDuration
		r.native.shared = &shared
	}
	return r, nil
}

// ReadFactors returns complete bounded safe metadata or no result. Unknown
// authority, overflow, corruption, cancelled context and unavailable storage
// fail closed. No secret, recipient address, OTP, proof or credential is read.
func (r *OTPListReader) ReadFactors(ctx context.Context, q mfa.FactorListQuery) (mfa.FactorListSnapshot, error) {
	if r == nil || r.native == nil {
		return mfa.FactorListSnapshot{}, identity.InvalidInputError{Field: "mfa_list"}
	}
	return r.native.ReadFactors(ctx, q)
}

// Keep the shared reader's bounds and recovery-set interpretation. UNION ALL
// preserves distinct native methods; the permanent factor-reference allocation
// makes IDs unique across owners. Limits precede JSON materialization and the
// shared active-count check forbids a partial/unsupported-method inventory.
const otpFactorListSQL = `WITH scope AS (
 SELECT a.tenant_id,a.user_id,a.version,a.active_factors,statement_timestamp() AS observed
 FROM identity_mfa.factor_authorities a JOIN identity.users u USING(tenant_id,user_id)
 WHERE a.tenant_id=$1 AND a.user_id=$2 AND u.status='active'
), native_candidates AS (
 SELECT t.tenant_id,t.user_id,t.factor_id,'totp'::text AS method,t.state,t.created_at,t.row_version,
 t.confirmed_at,''::text AS label
 FROM identity_mfa.totp_factors t JOIN scope s USING(tenant_id,user_id)
 WHERE t.state<>1 OR t.enrollment_expires_at>s.observed
 UNION ALL
 SELECT o.tenant_id,o.user_id,o.factor_id,'otp'::text,o.state,o.created_at,o.row_version,
 o.confirmed_at,''::text
 FROM identity_mfa.otp_factors o JOIN scope s USING(tenant_id,user_id)
 WHERE o.state<>1 OR o.enrollment_expires_at>s.observed
), native_factors AS (
 SELECT * FROM native_candidates ORDER BY factor_id LIMIT 101
), factors AS (
 SELECT factor_id,method,state,created_at,row_version,label FROM native_factors
 ORDER BY factor_id LIMIT 101
), factor_json AS (
 SELECT COALESCE(jsonb_agg(jsonb_build_object('ID',factor_id,'Method',method,'State',state,
 'CreatedAt',created_at,'Version',row_version,'Label',label) ORDER BY factor_id),'[]'::jsonb) AS value
 FROM factors
), active_sets AS (
 SELECT r.tenant_id,r.set_id,r.factor_id,r.code_count
 FROM identity_mfa.recovery_sets r JOIN scope s USING(tenant_id,user_id)
 JOIN native_factors f USING(tenant_id,user_id,factor_id)
 WHERE r.state=2 AND f.state=2 AND f.confirmed_at IS NOT NULL AND r.factor_method=f.method
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
