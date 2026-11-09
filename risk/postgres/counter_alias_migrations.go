package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// CounterKeyVersionMigrationSource adds nullable immutable alias metadata to
// installed protected counter charges. Allocate Version permanently after the
// protected-counter source. Historical rows stay NULL: their original aliases
// are unknown, not today's key set. There is no backfill, new journal or down SQL.
// Only repositories selecting RetainCounterKeyVersions require this suffix.
type CounterKeyVersionMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load is pure, cancellation-aware and preserves installed history bytes.
func (s CounterKeyVersionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version < 1 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_counter_alias_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(counterKeyVersionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_counter_key_versions", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// An existing charge may transfer generation, never rewrite the key history
// that was admitted with its immutable original counter fingerprint and time.
const counterKeyVersionSQL = `ALTER TABLE @schema@.counter_charges
 ADD COLUMN key_versions bigint[],
 ADD CONSTRAINT risk_counter_key_versions_shape CHECK(key_versions IS NULL OR
  (array_ndims(key_versions)=1 AND array_lower(key_versions,1)=1 AND cardinality(key_versions) BETWEEN 1 AND 4
   AND array_position(key_versions,NULL) IS NULL AND 0<ALL(key_versions) AND 4294967295>=ALL(key_versions)
   AND (cardinality(key_versions)<2 OR key_versions[1]>key_versions[2])
   AND (cardinality(key_versions)<3 OR key_versions[2]>key_versions[3])
   AND (cardinality(key_versions)<4 OR key_versions[3]>key_versions[4])));
CREATE FUNCTION @schema@.guard_counter_key_versions() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
 IF NEW.key_versions IS DISTINCT FROM OLD.key_versions THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='risk counter key versions immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER risk_counter_key_versions_immutable BEFORE UPDATE ON @schema@.counter_charges
 FOR EACH ROW EXECUTE FUNCTION @schema@.guard_counter_key_versions();
`
