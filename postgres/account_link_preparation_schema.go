package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// AccountLinkPreparationMigrationSource adds the closed original OAuth
// account-link preparation profile to the existing command journal. Base must
// include CounterPreparationMigrationSource; Version follows installed history.
// Profile 5 retains original declaration, generation and encrypted exchange
// output. It does not create a second workflow or permit another exchange after
// an uncertain start. Install before selecting the prepared account-link owner.
// Older profiles and migration checksums are unchanged. There is no down SQL.
type AccountLinkPreparationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independently owned forward history without database I/O.
// Invalid configuration and cancellation follow PreparationMigrationSource.
func (s AccountLinkPreparationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_account_link_preparation", accountLinkPreparationSchemaSQL)
}

// Profile 5 extends, rather than rewrites, the installed preparation constraint.
// A final root link plan needs retained output; only a definitive pre-exchange
// denial may be terminal without it. This is custody shape, not authorization.
const accountLinkPreparationSchemaSQL = `ALTER TABLE identity.commands
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
     OR state='aborted' AND preparation_started_generation IS NULL)))));
`
