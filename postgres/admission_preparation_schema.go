package postgres

import (
	"context"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// AdmissionPreparationMigrationSource appends forward support for the
// immutable externally admitted preparation profile. Base must include
// PreparationMigrationSource; Version must follow all selected history.
// Existing rows, preparation SQL/checksums and profile 1 remain unchanged.
// Old readers reject profile 2 rather than silently bypass admission. Install
// before enabling an externally admitted owner; no destructive down SQL exists.
type AdmissionPreparationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independently owned forward history without database IO.
// Invalid configuration and cancellation follow PreparationMigrationSource.
func (s AdmissionPreparationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_command_preparation_admission", admissionPreparationSchemaSQL)
}

const admissionPreparationSchemaSQL = `ALTER TABLE identity.commands
 DROP CONSTRAINT identity_preparation_shape,
 ADD CONSTRAINT identity_preparation_shape CHECK (
  num_nonnulls(preparation_profile,preparation_started_generation,preparation_ciphertext_generation,preparation_ciphertext)=0
  OR (preparation_profile IS NOT NULL AND preparation_profile IN (1,2) AND state IS NOT NULL
   AND generation IS NOT NULL
   AND (preparation_started_generation IS NULL OR preparation_started_generation<=generation)
   AND ((preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL)
    OR (preparation_started_generation IS NOT NULL AND preparation_ciphertext_generation IS NOT NULL
     AND preparation_ciphertext IS NOT NULL
     AND preparation_ciphertext_generation=preparation_started_generation
     AND octet_length(preparation_ciphertext) BETWEEN 1 AND 1048576))));
`
