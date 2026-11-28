package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// AdminRevokeAllMigrationSource adds administrative subject-version evidence and
// a separately installed active-session index to an existing session Schema.
// Version and IndexVersion are permanent 1..MaxInt64 history allocations after
// the installed prerequisites; IndexVersion must follow Version. The kernel
// command journal and session schema must already exist. No previous migration,
// session payload, or self-service revocation authority is changed.
//
// Apply both steps before enabling the administrative writer. Load selects an
// online concurrent index build outside a transaction; normal reads and writes
// remain available, but older transactions may delay it and it consumes build
// I/O and storage. A failed or cancelled build can leave an invalid index. Its
// name is not completion evidence: an operator must inspect pg_index.indisvalid
// and explicitly clean up an invalid index concurrently before retrying. Any
// adoption of an existing valid index requires explicit operator recovery;
// this source never silently adopts one. No destructive downgrade is provided.
type AdminRevokeAllMigrationSource struct {
	Schema                string
	Version, IndexVersion migrations.Version
}

var _ migrations.Source = AdminRevokeAllMigrationSource{}

// Load returns independently owned forward-only table and online-index history
// without I/O. Nil/cancelled contexts and invalid allocations produce no work.
// The table transaction bounds lock acquisition to five seconds; the concurrent
// index statement runs under the caller's bounded migrations Runner context.
// Calls are safe concurrently and do not retain caller-owned mutable state.
func (s AdminRevokeAllMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) || s.IndexVersion <= s.Version || s.IndexVersion > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_admin_revoke_all_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	schema := pgx.Identifier{s.Schema}.Sanitize()
	tableSQL := strings.ReplaceAll(adminRevokeAllSchemaSQL, "@schema@", schema)
	table, err := migrations.NewMigration(s.Version, "identity_session_admin_set_revocations", migrations.TransactionModeDefault, tableSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	indexSQL := strings.ReplaceAll(adminRevokeAllIndexSQL, "@schema@", schema)
	index, err := migrations.NewMigration(s.IndexVersion, "identity_session_admin_active_subject_order", migrations.TransactionModeNone, indexSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{table, index}, nil
}

// LoadOffline selects ordinary transactional index creation for an explicit
// offline installation or maintenance window, including Reference's atomic
// migration command, which does not accept transaction-none steps. It preserves
// the evidence-table migration but gives the index a different checksum. Select
// this history before first installation; it cannot replace already-applied
// concurrent history at the same version.
//
// Ordinary CREATE INDEX blocks writes until its enclosing transaction ends.
// The five-second local lock timeout bounds acquisition, not build time or
// transaction duration. The caller owns the offline window and bounded execution
// context. This method reuses Load's validation and performs no I/O.
func (s AdminRevokeAllMigrationSource) LoadOffline(ctx context.Context) ([]migrations.Migration, error) {
	history, err := s.Load(ctx)
	if err != nil {
		return nil, err
	}
	concurrent := history[1]
	sql := "SET LOCAL lock_timeout = '5s';\n" + strings.Replace(concurrent.UpSQL(), "CREATE INDEX CONCURRENTLY ", "CREATE INDEX ", 1)
	index, err := migrations.NewMigration(concurrent.Version(), concurrent.Name(), migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	history[1] = index
	return history, nil
}

// Zero is a valid first predecessor. The existing positive version domain owns
// the committed successor, and the unique subject/version key supports a backward
// index scan for the latest evidence without depending on prunable sessions.
const adminRevokeAllSchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.admin_set_revocations(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.admin.session-revoke-all'),
 user_id @schema@.scope_id NOT NULL,
 before_version numeric NOT NULL CHECK(before_version>=0 AND before_version<=18446744073709551614 AND scale(before_version)=0),
 subject_version @schema@.version NOT NULL,
 revoked_count integer NOT NULL CHECK(revoked_count BETWEEN 0 AND 100000),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 result_digest bytea NOT NULL CHECK(octet_length(result_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 UNIQUE(tenant_id,user_id,subject_version),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(subject_version=before_version+1)
);`

const adminRevokeAllIndexSQL = `CREATE INDEX CONCURRENTLY session_admin_active_subject_order ON @schema@.sessions(tenant_id,user_id,session_id) WHERE state='active';`
