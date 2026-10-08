package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// CSRFMigrationSource extends the installed session record constraint to admit
// digest-only synchronizer state. Schema selects the existing owned namespace;
// Version is a permanent 1..MaxInt64 slot after MigrationSource in the sole
// migration history. It rewrites no historical SQL, payload or receipt hash.
// Apply before enabling CSRF issuance. Old binaries remain valid for tokenless
// sessions and fail closed on schema-2 records; upgrade all relevant readers
// and writers before selecting the new profile. Zero is invalid.
type CSRFMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns forward-only transactional SQL without IO. The migrations
// Runner owns locking, allocation and commitment; cancellation is preserved.
func (s CSRFMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_csrf_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_csrf", migrations.TransactionModeDefault, strings.ReplaceAll(csrfSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// sessions_check is the exact cross-column binding constraint installed by
// the unchanged base migration. Replacing it is atomic with validation of all
// populated rows; malformed legacy data aborts the upgrade, not a bypass.
const csrfSchemaSQL = `ALTER TABLE @schema@.sessions DROP CONSTRAINT sessions_check;
ALTER TABLE @schema@.sessions ADD CONSTRAINT session_record_binding_v2 CHECK((
 record->>'TenantID'=tenant_id AND record->>'SessionID'=session_id
 AND record->>'UserID'=user_id AND record->>'FamilyID'=family_id
 AND (record->>'Version')::numeric=version
 AND (record->>'FamilyVersion')::numeric=family_version
 AND ((record->>'Schema'='1' AND NOT record ? 'CSRF')
 OR (record->>'Schema'='2' AND jsonb_typeof(record->'CSRF')='object'
 AND jsonb_typeof(record->'CSRF'->'Binding')='object'
 AND record->'CSRF'->'Binding'->>'TenantID'=tenant_id
 AND record->'CSRF'->'Binding'->>'SessionID'=session_id
 AND (record->'CSRF'->'Binding'->>'SessionVersion')::numeric=version
 AND jsonb_typeof(record->'CSRF'->'KeyVersion')='number'
 AND (record->'CSRF'->>'KeyVersion')::numeric BETWEEN 1 AND 4294967295
 AND trunc((record->'CSRF'->>'KeyVersion')::numeric)=(record->'CSRF'->>'KeyVersion')::numeric
 AND jsonb_typeof(record->'CSRF'->'Digest')='array'
 AND jsonb_array_length(record->'CSRF'->'Digest')=32))) IS TRUE);
`
