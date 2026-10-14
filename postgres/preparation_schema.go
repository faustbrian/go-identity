package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PreparationMigrationSource appends optional pre-generation custody columns
// to the existing command journal. It creates no second workflow store and
// does not enroll historical commands or grant generation/execution authority.
// Compose with a Base containing the kernel history and an explicit later
// Version. Install before enabling a preparation-aware native composition;
// legacy commands and migration checksums remain unchanged. No down SQL exists.
type PreparationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independent immutable forward history, without I/O. Nil inputs,
// empty history and a non-successor version fail; cancellation is preserved.
func (s PreparationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_command_preparation", preparationSchemaSQL)
}

func appendPreparationMigration(ctx context.Context, base migrations.Source, version migrations.Version, name, sql string) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(base) || version == 0 || version > migrations.Version(math.MaxInt64) {
		return nil, invalidPreparation()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidPreparation()
	}
	for _, m := range history {
		if m.Version() >= version {
			return nil, invalidPreparation()
		}
	}
	next, err := migrations.NewMigration(version, name, migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const preparationSchemaSQL = `ALTER TABLE identity.commands
 ADD COLUMN preparation_profile smallint,
 ADD COLUMN preparation_started_generation identity.version,
 ADD COLUMN preparation_ciphertext_generation identity.version,
 ADD COLUMN preparation_ciphertext bytea,
 ADD CONSTRAINT identity_preparation_shape CHECK (
  num_nonnulls(preparation_profile,preparation_started_generation,preparation_ciphertext_generation,preparation_ciphertext)=0
  OR (preparation_profile IS NOT NULL AND preparation_profile=1 AND state IS NOT NULL
   AND generation IS NOT NULL
   AND (preparation_started_generation IS NULL OR preparation_started_generation<=generation)
   AND ((preparation_ciphertext IS NULL AND preparation_ciphertext_generation IS NULL)
    OR (preparation_started_generation IS NOT NULL AND preparation_ciphertext_generation IS NOT NULL
     AND preparation_ciphertext IS NOT NULL
     AND preparation_ciphertext_generation=preparation_started_generation
     AND octet_length(preparation_ciphertext) BETWEEN 1 AND 1048576))));

CREATE FUNCTION identity.guard_command_preparation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
 IF (OLD.preparation_profile IS NOT NULL AND NEW.preparation_profile IS DISTINCT FROM OLD.preparation_profile)
 OR (OLD.preparation_started_generation IS NOT NULL AND NEW.preparation_started_generation IS DISTINCT FROM OLD.preparation_started_generation)
 OR (OLD.preparation_ciphertext IS NOT NULL AND (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
  OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation)) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='identity command preparation immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER identity_command_preparation_immutable BEFORE UPDATE OF preparation_profile,preparation_started_generation,preparation_ciphertext_generation,preparation_ciphertext ON identity.commands FOR EACH ROW EXECUTE FUNCTION identity.guard_command_preparation();
`
