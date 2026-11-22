package postgres

import "context"

// SSOOIDCSubjectAvailable reports whether the original transaction's tenant
// has no retained account for the exact trusted native SSO OIDC subject.
// A live or retired digest match, including a hash collision or an account
// with no usable credential association, returns false. Invalid scope is
// InvalidInput; storage failures are Unavailable. Cancellation and deadlines
// retain the repository's standard error semantics, always with false.
//
// Only the native sso.oidc.v1.<64 lowercase hex> provider namespace is accepted.
// Install SSOOIDCSubjectAvailabilityMigrationSource before enabling JIT so
// retained history has a tenant/digest access path. This bounded primary read
// does not authenticate a subject, grant provisioning permission, select a
// user, or lease absence. The original callback Work must recheck the same
// tuple, and the live-subject unique index must fence its actual account write.
func (r *Repository) SSOOIDCSubjectAvailable(ctx context.Context, q ProviderSigninAccountQuery) (bool, error) {
	if !r.validAccountRead(ctx) || !validSSOOIDCSubjectQuery(q) {
		return false, invalidAccountQuery()
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	var available bool
	err := r.pool.Raw().QueryRow(bounded, ssoOIDCSubjectAvailableSQL, string(q.TenantID), q.Provider, q.Issuer, q.Subject).Scan(&available)
	if err != nil {
		return false, readFailure(bounded, err)
	}
	if err := bounded.Err(); err != nil {
		return false, readFailure(bounded, err)
	}
	return available, nil
}

func validSSOOIDCSubjectQuery(q ProviderSigninAccountQuery) bool {
	return q.Validate() == nil && validSSOOIDCJITProviderNamespace(q.Provider)
}

// Keep this exact occupancy check shared with the original callback Work.
// Explicit live/retired branches use both partial digest indexes. The result
// is an existence check, even when unlink history contains duplicate tuples.
// The existing identity_account_subject_key CHECK owns the framed digest.
// No credential/user join may turn an ineligible existing link into absence.
const ssoOIDCSubjectAvailableSQL = `SELECT NOT EXISTS (
 SELECT 1 FROM identity.accounts
 WHERE tenant_id=$1 AND linked AND subject_key=sha256(convert_to(
 octet_length($2::text)::text||':'||$2::text||octet_length($3::text)::text||':'||$3::text||octet_length($4::text)::text||':'||$4::text,'UTF8'))
 UNION ALL
 SELECT 1 FROM identity.accounts
 WHERE tenant_id=$1 AND NOT linked AND subject_key=sha256(convert_to(
 octet_length($2::text)::text||':'||$2::text||octet_length($3::text)::text||':'||$3::text||octet_length($4::text)::text||':'||$4::text,'UTF8'))
)`
