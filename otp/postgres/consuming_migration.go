package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ConsumingMigrationSource retains the existing code-free encrypted original
// command projection in challenge custody. Install after MigrationSource using
// a distinct permanently allocated version. Existing rows are not rewritten or
// assigned invented authority. Historical reservations without this projection
// remain unreadable by native consuming recovery and fail closed. New columns
// are nullable for mixed-version readers; native consuming writers require them.
// Load is pure, forward-only, bounded and safe for concurrent calls.
type ConsumingMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = ConsumingMigrationSource{}

// Load returns an atomic forward extension; invalid configuration is redacted
// and cancellation preserved. No database, key material or code is accessed.
func (s ConsumingMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "otp_consuming_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_otp_original_consuming_custody", migrations.TransactionModeDefault, strings.ReplaceAll(consumingSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// Immutable expected input inside the existing participant, not a second flow
// state owner. Only initial issued->reserved may attach it; takeover and
// terminalization cannot replace or erase it.
const consumingSchemaSQL = `SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='30s';
ALTER TABLE @schema@.challenges
 ADD COLUMN consumer_envelope bytea,
 ADD COLUMN consumer_owner text COLLATE "C",
 ADD COLUMN consumer_record_requirement smallint,
 ADD COLUMN consumer_subject_requirement smallint,
 ADD CONSTRAINT otp_original_custody CHECK(
  (consumer_envelope IS NULL AND consumer_owner IS NULL AND consumer_record_requirement IS NULL AND consumer_subject_requirement IS NULL)
  OR (consumer_envelope IS NOT NULL AND consumer_owner IS NOT NULL AND consumer_record_requirement IS NOT NULL AND consumer_subject_requirement IS NOT NULL
      AND octet_length(consumer_envelope) BETWEEN 1 AND 8192 AND octet_length(consumer_owner) BETWEEN 1 AND 128
      AND consumer_record_requirement IN(1,2) AND consumer_subject_requirement IN(0,1)
      AND consumer_command_id IS NOT NULL AND state IN('reserved','finalized','released','revoked')));
CREATE FUNCTION @schema@.guard_original_custody() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
BEGIN
 IF TG_OP='INSERT' THEN
  IF NEW.consumer_envelope IS NOT NULL THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP original custody initial conflict'; END IF;
 ELSIF ROW(NEW.consumer_envelope,NEW.consumer_owner,NEW.consumer_record_requirement,NEW.consumer_subject_requirement)
 IS DISTINCT FROM ROW(OLD.consumer_envelope,OLD.consumer_owner,OLD.consumer_record_requirement,OLD.consumer_subject_requirement) THEN
  IF OLD.state<>'issued' OR NEW.state<>'reserved' OR OLD.consumer_envelope IS NOT NULL OR NEW.consumer_envelope IS NULL THEN
   RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='OTP original custody immutable';
  END IF;
 END IF;
 RETURN NEW;
END
$guard$;
CREATE TRIGGER otp_original_custody_guard BEFORE INSERT OR UPDATE ON @schema@.challenges FOR EACH ROW EXECUTE FUNCTION @schema@.guard_original_custody();
`
