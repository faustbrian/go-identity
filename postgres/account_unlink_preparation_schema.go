package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// AccountUnlinkPreparationMigrationSource adds profile 6 to the existing
// journal for original password-authorized account unlink. Base must include
// AccountLinkPreparationErasureValidationMigrationSource; Version follows the
// entire installed history. Install before selecting any unlink-preparation
// writer. Profiles 1..5 and their published migration bytes remain unchanged.
// The widened CHECK is enforced immediately for writes but NOT VALID avoids a
// scan under the DDL lock. Validate in a later transaction with the matching
// validation source. No down SQL recreates erased preparation credentials.
type AccountUnlinkPreparationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends independently owned forward history without database I/O.
// Invalid configuration and cancellation follow PreparationMigrationSource.
func (s AccountUnlinkPreparationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_account_unlink_preparation", accountUnlinkPreparationSQL)
}

// AccountUnlinkPreparationValidationMigrationSource validates the widened
// journal CHECK in a separate transaction. Base must include the expansion;
// Version follows it. Validation changes no rows or execution authority. Code
// rollback leaves both histories and original receipts intact; roll forward
// rather than deleting retained commands or recreating erased credentials.
type AccountUnlinkPreparationValidationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends forward validation without I/O. Invalid configuration and
// cancellation follow PreparationMigrationSource.
func (s AccountUnlinkPreparationValidationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_account_unlink_preparation_validation", accountUnlinkPreparationValidationSQL)
}

// Profile 6 retains the original declaration and exact encrypted issuer output
// until a definitive terminal receipt. Expanding the existing shape/guard keeps
// one journal and preserves both RP-start and profile-5 terminal erasure. This
// enforces storage custody, not permission to unlink or consume a password proof.
const accountUnlinkPreparationSQL = `SET LOCAL lock_timeout = '5s';
ALTER TABLE identity.commands
 DROP CONSTRAINT identity_preparation_shape,
 ADD CONSTRAINT identity_preparation_shape CHECK (
  num_nonnulls(preparation_profile,preparation_started_generation,preparation_ciphertext_generation,preparation_ciphertext,preparation_declaration)=0
  OR (preparation_profile IS NOT NULL AND preparation_profile IN (1,2,3,4,5,6) AND state IS NOT NULL
   AND generation IS NOT NULL
   AND ((preparation_profile IN (1,2) AND preparation_declaration IS NULL)
    OR (preparation_profile IN (3,4,5,6) AND (preparation_declaration IS NULL AND preparation_started_generation IS NULL
     OR preparation_declaration IS NOT NULL AND octet_length(preparation_declaration) BETWEEN 1 AND 65536)))
   AND (preparation_started_generation IS NULL OR preparation_started_generation<=generation)
   AND ((preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL)
    OR (preparation_started_generation IS NOT NULL AND preparation_ciphertext_generation IS NOT NULL
     AND preparation_ciphertext IS NOT NULL
     AND preparation_ciphertext_generation=preparation_started_generation
     AND octet_length(preparation_ciphertext) BETWEEN 1 AND 1048576))
   AND (preparation_profile NOT IN(5,6) OR (
    ((preparation_profile=5 AND purpose='identity.account.link-token')
     OR (preparation_profile=6 AND purpose='identity.account.unlink'))
    AND (command_plan IS NULL OR preparation_ciphertext IS NOT NULL
     OR state='aborted' AND preparation_started_generation IS NULL
     OR state IN('committed','aborted') AND preparation_started_generation IS NOT NULL))))) NOT VALID;

CREATE OR REPLACE FUNCTION identity.guard_command_preparation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
 rp_start boolean := OLD.purpose IN('identity.account.link-start','identity.oauth.signin-start');
 account_preparation boolean := (OLD.purpose='identity.account.link-token' AND OLD.preparation_profile=5)
  OR (OLD.purpose='identity.account.unlink' AND OLD.preparation_profile=6);
 erasing boolean := ((rp_start AND OLD.preparation_profile IN(1,2,3,4)) OR account_preparation)
  AND OLD.state='pending' AND NEW.state IN('committed','aborted')
  AND NEW.preparation_ciphertext IS NULL AND NEW.preparation_ciphertext_generation IS NULL;
BEGIN
 IF (OLD.preparation_profile IS NOT NULL AND NEW.preparation_profile IS DISTINCT FROM OLD.preparation_profile)
 OR (OLD.preparation_started_generation IS NOT NULL AND NEW.preparation_started_generation IS DISTINCT FROM OLD.preparation_started_generation)
 OR (OLD.preparation_ciphertext IS NOT NULL AND (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
  OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation) AND NOT erasing)
 OR ((rp_start OR account_preparation) AND OLD.state IN('committed','aborted') AND
  (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
   OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation)) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='identity command preparation immutable';
 END IF;
 RETURN NEW;
END;
$$;
`

const accountUnlinkPreparationValidationSQL = `SET LOCAL lock_timeout = '5s';
ALTER TABLE identity.commands VALIDATE CONSTRAINT identity_preparation_shape;
`
