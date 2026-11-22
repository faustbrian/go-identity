package postgres

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// The kernel has already locked the exact still-linked account in this Work.
// The vault is eligible only when its captured account and social-link versions
// match. Missing or stale custody is not successful erasure in this profile.
// There is no token read, decryption or network revocation.
func eraseAccountUnlinkVault(ctx context.Context, work kernel.AccountUnlinkWork, owner kernel.AccountUnlinkContributor, schema string) error {
	spec, err := work.PersistenceIntent(owner)
	if err != nil {
		return err
	}
	return eraseUnlinkProviderTokens(ctx, work.Exec, schema, spec.Change)
}

func eraseUnlinkProviderTokens(ctx context.Context, exec func(context.Context, string, ...any) (int64, error), schema string, change identity.AccountUnlinkChange) error {
	if ctx == nil || exec == nil || !rpSchemaName(schema) || change.TenantID == "" || change.UserID == "" ||
		change.AccountID == "" || change.ExpectedAccountVersion == 0 || change.ExpectedSocialLinkVersion == 0 {
		return identity.InvalidInputError{Field: "oauth_unlink_vault"}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sql := strings.ReplaceAll(unlinkProviderTokensSQL, "@schema@", rpQuotedSchema(schema))
	count, err := exec(ctx, sql, string(change.TenantID), string(change.AccountID), string(change.UserID),
		change.ExpectedAccountVersion, change.ExpectedSocialLinkVersion)
	if err != nil {
		return rpTokenVaultFailure(ctx, true)
	}
	if count != 1 {
		return identity.ConflictError{}
	}
	return nil
}

const unlinkProviderTokensSQL = `DELETE FROM @schema@.token_sets
 WHERE tenant_id=$1 AND account_id=$2 AND user_id=$3
 AND account_version=$4::numeric AND social_link_version=$5::numeric`
