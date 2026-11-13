package postgres

import (
	"context"
	"strconv"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// This checks actual current association in addition to credential epochs.
// In particular, an enabled reference alone is not a live linked account.
const linkedProviderCredentialSelect = `SELECT c.expires_at FROM identity.users u
 JOIN identity.credential_references c ON c.tenant_id=u.tenant_id AND c.user_id=u.user_id
 JOIN identity.account_credentials m ON m.tenant_id=c.tenant_id AND m.user_id=c.user_id AND m.credential_id=c.credential_id
 JOIN identity.accounts a ON a.tenant_id=m.tenant_id AND a.user_id=m.user_id AND a.account_id=m.account_id
 WHERE u.tenant_id=$1 AND u.user_id=$2 AND c.credential_id=$3 AND c.kind=3 AND c.owner='identity/oauth' AND c.version=$4::numeric AND c.enabled
 AND u.status='active' AND u.authority_version=$5::numeric AND u.identifier_version=$6::numeric AND u.credential_version=$7::numeric AND a.linked LIMIT 2`

func validProviderSessionCredential(a CredentialAdmission) bool {
	c := a.Credential
	return c.Validate(c.TenantID, c.UserID) == nil && c.Kind == identity.CredentialProvider && c.Owner == "identity/oauth" && a.UserAuthorityVersion != 0 && a.IdentifierAuthorityVersion != 0 && a.CredentialAuthorityVersion != 0
}
func providerSessionCredentialArgs(a CredentialAdmission) []any {
	return []any{string(a.Credential.TenantID), string(a.Credential.UserID), string(a.Credential.ID), strconv.FormatUint(a.Credential.Version, 10), strconv.FormatUint(a.UserAuthorityVersion, 10), strconv.FormatUint(a.IdentifierAuthorityVersion, 10), strconv.FormatUint(a.CredentialAuthorityVersion, 10)}
}

func linkedProviderExpiry(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}) (*time.Time, error) {
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return nil, identity.UnavailableError{}
		}
		return nil, identity.ForbiddenError{}
	}
	var expires *time.Time
	if rows.Scan(&expires) != nil || rows.Next() || rows.Err() != nil {
		return nil, identity.UnavailableError{}
	}
	return expires, nil
}

// CheckLinkedProviderCredential performs bounded primary eligibility reads for
// the exact original provider reference and user/security epochs. Missing,
// disabled, expired, foreign or unlinked authority denies; ambiguous association
// and storage failure are unavailable. The read creates no proof, snapshot
// lease, transaction or current-session permission. Preserve the earliest
// contributing read-start budget, and repeat under Work before a mutation.
func (r *Repository) CheckLinkedProviderCredential(ctx context.Context, expected CredentialAdmission) error {
	if !r.validAccountRead(ctx) || !validProviderSessionCredential(expected) {
		return invalidAccountQuery()
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	rows, err := r.pool.Raw().Query(bounded, linkedProviderCredentialSelect, providerSessionCredentialArgs(expected)...)
	if err != nil {
		return readFailure(bounded, err)
	}
	expires, err := linkedProviderExpiry(rows)
	if err != nil {
		return err
	}
	var now time.Time
	if err := r.pool.Raw().QueryRow(bounded, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return readFailure(bounded, err)
	}
	if expires != nil && !now.Before(*expires) {
		return identity.ForbiddenError{}
	}
	return bounded.Err()
}

// RequireLinkedProviderCredential retains the current linked association and
// user/credential locks for this exact registered native owner's same-user Work.
// It also repeats exclusive expiry AFTER lock acquisition, so waiting cannot
// preserve an expired credential. Missing/stale authority poisons Work even if
// ignored. Caller must additionally fence directory, policy, factors and session
// state; this creates neither authentication nor permission to mutate an account.
func (w Work) RequireLinkedProviderCredential(ctx context.Context, owner FeatureExecutionContributor, expected CredentialAdmission) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if !validProviderSessionCredential(expected) {
		return w.fail(ctx, invalidWork())
	}
	b, _, _, err := w.FeatureScope(owner)
	if err != nil || b.TenantID != expected.Credential.TenantID || b.UserID != expected.Credential.UserID {
		return w.fail(ctx, invalidWork())
	}
	// Preserve existing user/credential-before-account lock ownership.
	if _, err := w.RequireActiveCredential(ctx, owner, expected); err != nil {
		return err
	}
	rows, err := w.Query(ctx, linkedProviderCredentialSelect+` FOR SHARE OF a,m`, providerSessionCredentialArgs(expected)...)
	if err != nil {
		return err
	}
	expires, err := linkedProviderExpiry(rows)
	if err != nil {
		return w.fail(ctx, err)
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if expires != nil && !now.Before(*expires) {
		return w.fail(ctx, identity.ForbiddenError{})
	}
	return nil
}
