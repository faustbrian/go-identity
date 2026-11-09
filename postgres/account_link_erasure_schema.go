package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// AccountLinkPreparationErasureMigrationSource permits terminal erasure of
// profile-5 provider-response/issuance-checkpoint ciphertext. Base must include
// AccountLinkPreparationMigrationSource and any selected RP-start erasure
// migration; Version follows that entire history. Install before enabling the
// terminal-erasure writer. Existing history and populated rows are unchanged.
// The replacement check is NOT VALID to avoid scanning under the DDL lock;
// new writes enforce it immediately, and the old validated check was stricter.
// Validate separately with AccountLinkPreparationErasureValidationMigrationSource.
// No down migration can restore erased secrets.
type AccountLinkPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independent forward history without database I/O. Invalid
// configuration and cancellation follow PreparationMigrationSource.
func (s AccountLinkPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_account_link_preparation_erasure", accountLinkPreparationErasureSQL)
}

// AccountLinkPreparationErasureValidationMigrationSource validates the relaxed
// custody check in a later transaction, without retaining the preceding DDL's
// exclusive table lock during the scan. Base must include the erasure migration;
// Version follows it. Validation changes no rows and grants no execution authority.
type AccountLinkPreparationErasureValidationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends the forward-only constraint validation without database I/O.
// Invalid configuration and cancellation follow PreparationMigrationSource.
func (s AccountLinkPreparationErasureValidationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_account_link_preparation_erasure_validation", accountLinkPreparationErasureValidationSQL)
}

// TRANSACTION_CONTRACT.md requires terminal provider-response erasure without
// losing replay authority. Profile 5 retains its original start/declaration and
// final plan, while pending output remains immutable. The existing RP-start
// exception is preserved: replacing this shared guard must not revoke it.
const accountLinkPreparationErasureSQL = `SET LOCAL lock_timeout = '5s';
ALTER TABLE identity.commands
 DROP CONSTRAINT identity_preparation_shape,
 ADD CONSTRAINT identity_preparation_shape CHECK (
  num_nonnulls(preparation_profile,preparation_started_generation,preparation_ciphertext_generation,preparation_ciphertext,preparation_declaration)=0
  OR (preparation_profile IS NOT NULL AND preparation_profile IN (1,2,3,4,5) AND state IS NOT NULL
   AND generation IS NOT NULL
   AND ((preparation_profile IN (1,2) AND preparation_declaration IS NULL)
    OR (preparation_profile IN (3,4,5) AND (preparation_declaration IS NULL AND preparation_started_generation IS NULL
     OR preparation_declaration IS NOT NULL AND octet_length(preparation_declaration) BETWEEN 1 AND 65536)))
   AND (preparation_started_generation IS NULL OR preparation_started_generation<=generation)
   AND ((preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL)
    OR (preparation_started_generation IS NOT NULL AND preparation_ciphertext_generation IS NOT NULL
     AND preparation_ciphertext IS NOT NULL
     AND preparation_ciphertext_generation=preparation_started_generation
     AND octet_length(preparation_ciphertext) BETWEEN 1 AND 1048576))
   AND (preparation_profile<>5 OR (purpose='identity.account.link-token'
    AND (command_plan IS NULL OR preparation_ciphertext IS NOT NULL
     OR state='aborted' AND preparation_started_generation IS NULL
     OR state IN('committed','aborted') AND preparation_started_generation IS NOT NULL))))) NOT VALID;

CREATE OR REPLACE FUNCTION identity.guard_command_preparation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
 rp_start boolean := OLD.purpose IN('identity.account.link-start','identity.oauth.signin-start');
 link_preparation boolean := OLD.purpose='identity.account.link-token' AND OLD.preparation_profile=5;
 erasing boolean := ((rp_start AND OLD.preparation_profile IN(1,2,3,4)) OR link_preparation)
  AND OLD.state='pending' AND NEW.state IN('committed','aborted')
  AND NEW.preparation_ciphertext IS NULL AND NEW.preparation_ciphertext_generation IS NULL;
BEGIN
 IF (OLD.preparation_profile IS NOT NULL AND NEW.preparation_profile IS DISTINCT FROM OLD.preparation_profile)
 OR (OLD.preparation_started_generation IS NOT NULL AND NEW.preparation_started_generation IS DISTINCT FROM OLD.preparation_started_generation)
 OR (OLD.preparation_ciphertext IS NOT NULL AND (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
  OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation) AND NOT erasing)
 OR ((rp_start OR link_preparation) AND OLD.state IN('committed','aborted') AND
  (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
   OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation)) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='identity command preparation immutable';
 END IF;
 RETURN NEW;
END;
$$;
`

const accountLinkPreparationErasureValidationSQL = `SET LOCAL lock_timeout = '5s';
ALTER TABLE identity.commands VALIDATE CONSTRAINT identity_preparation_shape;
`
