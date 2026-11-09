package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OAuthRPPreparationErasureMigrationSource permits terminal secret erasure only
// for the closed OAuth RP-start operations. Base must include preparation and
// counter-preparation history; Version follows every installed migration. Old
// history/checksums and all other operations' immutability are unchanged. Install
// before enabling RP initiation. This creates no new journal or replay owner.
type OAuthRPPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independently owned forward-only history without IO. Nil,
// cancellation and successor-version rules follow PreparationMigrationSource.
// There is no destructive down SQL and no permission to erase pending output.
func (s OAuthRPPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_oauth_rp_preparation_erasure", oauthRPPreparationErasureSQL)
}

// An RP start copies encrypted generated custody into its native row in the
// same transaction. Keeping the journal copy after terminalization would defeat
// that row's later PKCE erasure. Permit only this terminal transition, retaining
// the original start generation/declaration and forbidding secret resurrection.
const oauthRPPreparationErasureSQL = `CREATE OR REPLACE FUNCTION identity.guard_command_preparation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
 rp_start boolean := OLD.purpose IN('identity.account.link-start','identity.oauth.signin-start');
 erasing boolean := rp_start AND OLD.state='pending' AND NEW.state IN('committed','aborted')
  AND OLD.preparation_profile IN(1,2,3,4)
  AND NEW.preparation_ciphertext IS NULL AND NEW.preparation_ciphertext_generation IS NULL;
BEGIN
 IF (OLD.preparation_profile IS NOT NULL AND NEW.preparation_profile IS DISTINCT FROM OLD.preparation_profile)
 OR (OLD.preparation_started_generation IS NOT NULL AND NEW.preparation_started_generation IS DISTINCT FROM OLD.preparation_started_generation)
 OR (OLD.preparation_ciphertext IS NOT NULL AND (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
  OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation) AND NOT erasing)
 OR (rp_start AND OLD.state IN('committed','aborted') AND
  (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
   OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation)) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='identity command preparation immutable';
 END IF;
 RETURN NEW;
END;
$$;
`
