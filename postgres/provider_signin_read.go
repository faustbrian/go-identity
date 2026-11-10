package postgres

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// ProviderSigninAccountQuery names the exact provider subject authenticated by
// the configured native provider. These scalars contain neither its assertion
// nor permission to sign in. Subject/issuer are opaque and never normalized.
// Tenant selection must already be fixed by the original RP transaction, not
// a provider claim or a callback's customer-selected identifier.
type ProviderSigninAccountQuery struct {
	TenantID                  identity.TenantID
	Provider, Issuer, Subject string
}

// Validate checks the existing identity-owned provider metadata bounds only.
// It performs no lookup, provider validation or authorization.
func (q ProviderSigninAccountQuery) Validate() error {
	// Reuse Account's structural tuple contract; these local placeholder IDs
	// are never persisted, returned, selected as a user or used for admission.
	shape := identity.Account{TenantID: q.TenantID, UserID: "query", ID: "query", Provider: q.Provider, Issuer: q.Issuer, Subject: q.Subject, Version: 1}
	if shape.Validate(q.TenantID, shape.UserID) != nil {
		return invalidAccountQuery()
	}
	return nil
}

// Format excludes correlated provider subjects from diagnostics.
func (ProviderSigninAccountQuery) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ProviderSigninAccountQuery(redacted)"))
}

// MarshalJSON prevents implicit disclosure of provider identity correlation.
func (ProviderSigninAccountQuery) MarshalJSON() ([]byte, error) { return nil, invalidAccountQuery() }

// MarshalText prevents implicit disclosure of provider identity correlation.
func (ProviderSigninAccountQuery) MarshalText() ([]byte, error) { return nil, invalidAccountQuery() }

// GetProviderSigninAccount resolves one existing live provider account and its
// exact associated credential/security epochs in a single bounded primary
// snapshot. Absent, blocked, disabled, unlinked or expired authority uniformly
// returns Forbidden; malformed input is InvalidInput, ambiguous/corrupt data
// and storage failures are Unavailable. Caller cancellation is preserved.
// Multiple credential associations deny rather than selecting a convenient one.
//
// This trusted native read is not provider authentication, a positive validity
// lease or implicit account linking. Freeze it in the original callback intent,
// bind the session to that same user/credential and recheck with
// RequireOAuthSigninProviderAccount in the sole transaction. Factor, current
// provider configuration, policy/risk and browser/state custody remain separate
// mandatory owners. No transaction, account, session or goroutine is created.
func (r *Repository) GetProviderSigninAccount(ctx context.Context, q ProviderSigninAccountQuery) (ProviderAccountAdmission, error) {
	if !r.validAccountRead(ctx) || q.Validate() != nil {
		return ProviderAccountAdmission{}, invalidAccountQuery()
	}
	bounded, stop := context.WithTimeout(ctx, r.maximumDuration)
	defer stop()
	rows, err := r.pool.Raw().Query(bounded, `SELECT a.tenant_id,a.user_id,a.account_id,a.provider,a.issuer,a.subject,
 a.version::text,a.social_link_version::text,c.credential_id,c.kind,c.owner,c.version::text,c.enabled,c.expires_at,
 u.status,u.authority_version::text,u.identifier_version::text,u.credential_version::text,clock_timestamp()
 FROM identity.accounts a JOIN identity.users u ON u.tenant_id=a.tenant_id AND u.user_id=a.user_id
 JOIN identity.account_credentials m ON m.tenant_id=a.tenant_id AND m.user_id=a.user_id AND m.account_id=a.account_id
 JOIN identity.credential_references c ON c.tenant_id=m.tenant_id AND c.user_id=m.user_id AND c.credential_id=m.credential_id
 WHERE a.tenant_id=$1 AND a.linked AND a.subject_key=sha256(convert_to(
 octet_length($2::text)::text||':'||$2::text||octet_length($3::text)::text||':'||$3::text||octet_length($4::text)::text||':'||$4::text,'UTF8'))
 LIMIT 2`, string(q.TenantID), q.Provider, q.Issuer, q.Subject)
	if err != nil {
		return ProviderAccountAdmission{}, readFailure(bounded, err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return ProviderAccountAdmission{}, readFailure(bounded, err)
		}
		return ProviderAccountAdmission{}, identity.ForbiddenError{}
	}
	var tenant, user, account, provider, issuer, subject, accountVersion, linkVersion string
	var credential, owner, credentialVersion, status, userEpoch, identifierEpoch, credentialEpoch string
	var kind int16
	var enabled bool
	var expires *time.Time
	var now time.Time
	if err := rows.Scan(&tenant, &user, &account, &provider, &issuer, &subject,
		&accountVersion, &linkVersion, &credential, &kind, &owner, &credentialVersion, &enabled, &expires,
		&status, &userEpoch, &identifierEpoch, &credentialEpoch, &now); err != nil {
		return ProviderAccountAdmission{}, readFailure(bounded, err)
	}
	if rows.Next() {
		return ProviderAccountAdmission{}, identity.UnavailableError{}
	}
	if err := rows.Err(); err != nil {
		return ProviderAccountAdmission{}, readFailure(bounded, err)
	}
	rows.Close()
	if bounded.Err() != nil {
		return ProviderAccountAdmission{}, readFailure(bounded, bounded.Err())
	}
	if tenant != string(q.TenantID) || provider != q.Provider || issuer != q.Issuer || subject != q.Subject || kind != int16(identity.CredentialProvider) || owner != "identity/oauth" || !postgresExactTime(now.UTC()) {
		return ProviderAccountAdmission{}, identity.UnavailableError{}
	}
	if status != string(identity.StatusActive) || !enabled || expires != nil && !now.Before(*expires) {
		return ProviderAccountAdmission{}, identity.ForbiddenError{}
	}
	versionsValid := true
	version := func(raw string) uint64 {
		value, err := parseAccountVersion(raw)
		if err != nil {
			versionsValid = false
		}
		return value
	}
	out := ProviderAccountAdmission{
		Account: identity.Account{
			TenantID: identity.TenantID(tenant), UserID: identity.UserID(user),
			ID: identity.AccountID(account), Provider: provider, Issuer: issuer,
			Subject: subject, Version: version(accountVersion),
		},
		SocialLinkVersion: version(linkVersion),
		Credential: CredentialAdmission{
			Credential: identity.CredentialRef{
				TenantID: identity.TenantID(tenant), UserID: identity.UserID(user),
				ID: identity.CredentialID(credential), Kind: identity.CredentialProvider,
				Owner: owner, Version: version(credentialVersion),
			},
			UserAuthorityVersion: version(userEpoch), IdentifierAuthorityVersion: version(identifierEpoch),
			CredentialAuthorityVersion: version(credentialEpoch),
		},
	}
	if !versionsValid || !validSigninAccount(out) {
		return ProviderAccountAdmission{}, identity.UnavailableError{}
	}
	return out, nil
}
