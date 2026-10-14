package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// CounterPreparationMigrationSource appends protected-counter preparation to
// the existing command journal. Base must include AdmissionPreparationMigrationSource;
// Version follows installed history. Profiles 3/4 freeze the original code-free
// declaration before a counter charge and retain it across retries. Old readers
// reject these profiles; legacy rows and checksums remain unchanged. Install
// before selecting counters with ExecutePreparedFeature. No down SQL is provided.
type CounterPreparationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independently owned forward history without database IO.
// Nil, cancellation and version semantics follow PreparationMigrationSource.
func (s CounterPreparationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_command_preparation_counters", counterPreparationSchemaSQL)
}

const counterPreparationSchemaSQL = `ALTER TABLE identity.commands
 ADD COLUMN preparation_declaration bytea,
 DROP CONSTRAINT identity_preparation_shape,
 ADD CONSTRAINT identity_preparation_shape CHECK (
  num_nonnulls(preparation_profile,preparation_started_generation,preparation_ciphertext_generation,preparation_ciphertext,preparation_declaration)=0
  OR (preparation_profile IS NOT NULL AND preparation_profile IN (1,2,3,4) AND state IS NOT NULL
   AND generation IS NOT NULL
   AND ((preparation_profile IN (1,2) AND preparation_declaration IS NULL)
    OR (preparation_profile IN (3,4) AND (preparation_declaration IS NULL AND preparation_started_generation IS NULL
     OR preparation_declaration IS NOT NULL AND octet_length(preparation_declaration) BETWEEN 1 AND 65536)))
   AND (preparation_started_generation IS NULL OR preparation_started_generation<=generation)
   AND ((preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL)
    OR (preparation_started_generation IS NOT NULL AND preparation_ciphertext_generation IS NOT NULL
     AND preparation_ciphertext IS NOT NULL
     AND preparation_ciphertext_generation=preparation_started_generation
     AND octet_length(preparation_ciphertext) BETWEEN 1 AND 1048576))));

CREATE FUNCTION identity.guard_preparation_declaration() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
 IF OLD.preparation_declaration IS NOT NULL AND NEW.preparation_declaration IS DISTINCT FROM OLD.preparation_declaration THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='identity preparation declaration immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER identity_preparation_declaration_immutable BEFORE UPDATE OF preparation_declaration ON identity.commands FOR EACH ROW EXECUTE FUNCTION identity.guard_preparation_declaration();
`
