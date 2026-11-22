package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OAuthProviderRefreshErasureMigrationSource permits terminal erasure of
// provider-refresh output for admission-gated preparation profiles 2 and 4.
// Base must include AccountUnlinkPreparationValidationMigrationSource and
// Version must follow the installed history. Install before enabling the native
// refresh writer. There is no row rewrite, backfill, or down migration.
type OAuthProviderRefreshErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends forward history without database I/O.
func (s OAuthProviderRefreshErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_oauth_provider_refresh_erasure", oauthProviderRefreshErasureSQL)
}

// The existing shape permits a terminal profile 2 or 4 without temporary
// output. This replacement adds only the precise immutable-trigger exception;
// it preserves prior RP start, account link and unlink custody rules.
const oauthProviderRefreshErasureSQL = `SET LOCAL lock_timeout = '5s';
CREATE OR REPLACE FUNCTION identity.guard_command_preparation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
 rp_start boolean := OLD.purpose IN('identity.account.link-start','identity.oauth.signin-start');
 account_preparation boolean := (OLD.purpose='identity.account.link-token' AND OLD.preparation_profile=5)
  OR (OLD.purpose='identity.account.unlink' AND OLD.preparation_profile=6);
 provider_refresh boolean := OLD.purpose='identity.account.refresh-token' AND OLD.preparation_profile IN(2,4);
 erasing boolean := ((rp_start AND OLD.preparation_profile IN(1,2,3,4)) OR account_preparation OR provider_refresh)
  AND OLD.state='pending' AND NEW.state IN('committed','aborted')
  AND NEW.preparation_ciphertext IS NULL AND NEW.preparation_ciphertext_generation IS NULL;
BEGIN
 IF (OLD.preparation_profile IS NOT NULL AND NEW.preparation_profile IS DISTINCT FROM OLD.preparation_profile)
 OR (OLD.preparation_started_generation IS NOT NULL AND NEW.preparation_started_generation IS DISTINCT FROM OLD.preparation_started_generation)
 OR (OLD.preparation_ciphertext IS NOT NULL AND (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
  OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation) AND NOT erasing)
 OR ((rp_start OR account_preparation OR provider_refresh) AND OLD.state IN('committed','aborted') AND
  (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
   OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation)) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='identity command preparation immutable';
 END IF;
 RETURN NEW;
END;
$$;
`
