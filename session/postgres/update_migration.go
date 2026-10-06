package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// UpdateMigrationSource installs non-authoritative labels and retained update
// participant evidence after the existing session/kernel history. Version is
// a permanent 1..MaxInt64 slot. It rewrites no existing row or checksum and
// does not change positional old-binary session writes or the closed codec.
// Current labels cascade with payload deletion; historical evidence stores only
// their digest, not plaintext. No destructive rollback/cleanup is supplied.
type UpdateMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load validates allocation/cancellation and returns independently owned,
// forward-only transactional SQL without IO. Use the sole migration Runner.
func (s UpdateMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_update_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_metadata", migrations.TransactionModeDefault, strings.ReplaceAll(updateSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const updateSchemaSQL = `CREATE TABLE @schema@.session_labels(
 tenant_id @schema@.scope_id NOT NULL,
 session_id @schema@.scope_id NOT NULL,
 label text NOT NULL CHECK(octet_length(label)<=128 AND label !~ U&'[\0001-\001F\007F-\009F]'),
 PRIMARY KEY(tenant_id,session_id),
 FOREIGN KEY(tenant_id,session_id) REFERENCES @schema@.sessions(tenant_id,session_id) ON DELETE CASCADE
);
CREATE TABLE @schema@.session_updates(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.session.update'),
 user_id @schema@.scope_id NOT NULL,
 session_id @schema@.scope_id NOT NULL,
 family_id @schema@.scope_id NOT NULL,
 before_version @schema@.version NOT NULL,
 after_version @schema@.version NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 successor_digest bytea NOT NULL CHECK(octet_length(successor_digest)=32),
 label_digest bytea NOT NULL CHECK(octet_length(label_digest)=32),
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
 source_record jsonb NOT NULL CHECK(jsonb_typeof(source_record)='object' AND octet_length(source_record::text)<=32768),
 successor_record jsonb NOT NULL CHECK(jsonb_typeof(successor_record)='object' AND octet_length(successor_record::text)<=32768),
 PRIMARY KEY(tenant_id,command_id),
 UNIQUE(tenant_id,session_id,before_version),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(after_version=before_version+1)
);
`
