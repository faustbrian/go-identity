package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// RevokeOneMigrationSource appends terminal single-session evidence to the
// unchanged base/family history. Version is a permanent allocation greater
// than Base.Version and at most MaxInt64; compose issuance separately when
// selected. No old record, snapshot or migration is rewritten. Load performs
// no IO; calls are concurrency-safe and have no destructive down migration.
type RevokeOneMigrationSource struct {
	Base    RevocationMigrationSource
	Version migrations.Version
}

// Load returns independently owned forward-only history. Missing or invalid
// base/version and nil contexts fail; cancellation retains its classification.
func (s RevokeOneMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_migration"}
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(revokeOneSchemaSQL, "@schema@", pgx.Identifier{s.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_single_revocations", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, m), nil
}

// No session-payload FK: terminal evidence must survive payload pruning. Its
// command FK preserves the exact shared journal authority for reconciliation.
const revokeOneSchemaSQL = `CREATE TABLE @schema@.session_revocations(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.session.revoke-one'),
 user_id @schema@.scope_id NOT NULL,
 session_id @schema@.scope_id NOT NULL,
 before_version @schema@.version NOT NULL,
 after_version @schema@.version NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 record_digest bytea NOT NULL CHECK(octet_length(record_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 UNIQUE(tenant_id,session_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(after_version=before_version+1)
);`
