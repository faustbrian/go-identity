package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// CleanupMigrationSource adds an owner/expiry index and retained cleanup result
// evidence at a permanent slot after base/rotation history. It never changes
// existing rows/checksums or supplies a destructive downgrade. Transactional
// index installation may block writes; budget populated rollout explicitly.
// Retained results have no session FK and outlive live-payload pruning.
type CleanupMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward migration without IO; zero, invalid or cancelled
// input fails before composition. Apply through the sole migrations Runner.
func (s CleanupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_cleanup_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(cleanupSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_cleanup", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const cleanupSchemaSQL = `CREATE INDEX session_owner_expiry ON @schema@.sessions(tenant_id,user_id,expires_at,session_id);
CREATE TABLE @schema@.cleanup_results(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.session.expire'),
 user_id @schema@.scope_id NOT NULL,
 considered_limit integer NOT NULL CHECK(considered_limit BETWEEN 1 AND 10000),
 deleted_count integer NOT NULL CHECK(deleted_count BETWEEN 0 AND considered_limit),
 observed_at @schema@.instant NOT NULL,
 remaining_lag_ns bigint NOT NULL CHECK(remaining_lag_ns BETWEEN 0 AND 31536000000000000),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)
);`
