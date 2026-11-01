package postgres

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// ProviderAccountAdmission freezes an exact provider account, its independent
// social-link version and original kernel credential authority. None of these
// scalar observations is provider proof or current authentication authority.
// The native owner must bind them into its immutable command before reservation.
type ProviderAccountAdmission struct {
	Account           identity.Account
	SocialLinkVersion uint64
	Credential        CredentialAdmission
}

// Format excludes provider subjects and correlated credential scope.
func (ProviderAccountAdmission) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.ProviderAccountAdmission(redacted)"))
}

// MarshalJSON prevents accidental export of correlated admission state.
func (ProviderAccountAdmission) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// RequireActiveProviderAccount checks current identity-owned account and
// credential authority during the exact registered participant's invocation.
// It retains primary user, credential, link and association share locks until
// the existing coordinator closes Work. Missing, unlinked, moved, disabled,
// expired or stale authority denies and poisons Work, including ignored errors.
// AccountMigrationSource and credential authority history must be installed.
//
// The clock sample follows all lock acquisition and a final credential expiry
// check; it neither renews original evidence nor constitutes a validity lease.
// Provider configuration/social-connection, cryptographic proof, current factor
// policy, authorization, risk and atomic one-use effects remain separate owning
// checks. This method never issues a session, mutates rows, starts a transaction,
// performs network I/O or retains a callback/handle. Success alone cannot
// authenticate a provider credential or admit a social callback.
func (w Work) RequireActiveProviderAccount(ctx context.Context, p FeatureExecutionContributor, expected ProviderAccountAdmission) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	b, _, _, err := w.FeatureScope(p)
	if err != nil {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	a, c := expected.Account, expected.Credential
	if a.Validate(b.TenantID, b.UserID) != nil || expected.SocialLinkVersion == 0 || c.Credential.Validate(b.TenantID, b.UserID) != nil || c.Credential.Kind != identity.CredentialProvider || c.UserAuthorityVersion == 0 || c.IdentifierAuthorityVersion == 0 || c.CredentialAuthorityVersion == 0 {
		return time.Time{}, w.fail(ctx, invalidWork())
	}
	// Keep the existing user/credential lock order. A later link-row wait must
	// not let the earlier credential observation survive its exclusive expiry.
	if _, err := w.requireActiveCredential(ctx, b, c); err != nil {
		return time.Time{}, err
	}
	rows, err := w.Query(ctx, `SELECT a.account_id,a.provider,a.issuer,a.subject,a.version::text,a.social_link_version::text,a.linked
 FROM identity.accounts a JOIN identity.account_credentials m
 ON m.tenant_id=a.tenant_id AND m.user_id=a.user_id AND m.account_id=a.account_id
 WHERE a.tenant_id=$1 AND a.user_id=$2 AND a.account_id=$3 AND m.credential_id=$4
 FOR SHARE OF a,m`, string(b.TenantID), string(b.UserID), string(a.ID), string(c.Credential.ID))
	if err != nil {
		return time.Time{}, err
	}
	if !rows.Next() {
		err := rows.Err()
		rows.Close()
		if err != nil {
			return time.Time{}, err
		}
		return time.Time{}, w.fail(ctx, identity.ForbiddenError{})
	}
	current := identity.Account{TenantID: b.TenantID, UserID: b.UserID}
	var id, version, socialVersion string
	var linked bool
	err = rows.Scan(&id, &current.Provider, &current.Issuer, &current.Subject, &version, &socialVersion, &linked)
	if err != nil {
		rows.Close()
		return time.Time{}, err
	}
	if rows.Next() {
		rows.Close()
		return time.Time{}, w.fail(ctx, identity.UnavailableError{})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return time.Time{}, err
	}
	current.ID = identity.AccountID(id)
	current.Version, err = parseAccountVersion(version)
	if err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	social, err := parseAccountVersion(socialVersion)
	if err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	if !linked || current != a || social != expected.SocialLinkVersion {
		return time.Time{}, w.fail(ctx, identity.ForbiddenError{})
	}
	return w.requireActiveCredential(ctx, b, c)
}
