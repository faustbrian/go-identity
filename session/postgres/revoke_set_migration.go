package postgres

import (
	"context"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
	"math"
	"strings"
)

// RevokeSetMigrationSource adds bounded bulk-command evidence and its selection
// index to an installed session schema through the sole migrations history.
// Schema must match the base; Version is a permanent later 1..MaxInt64 slot.
// Existing records/checksums are unchanged. The transactional index build may
// block writes on populated deployments; schedule that bounded rollout explicitly.
// No destructive down migration is provided. Calls perform no IO and are safe
// concurrently. Evidence has no session FK so payload pruning cannot erase it.
type RevokeSetMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one independently owned forward migration; nil/cancelled context
// or invalid schema/version fails before composition. Install through Runner.
func (s RevokeSetMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_set_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(revokeSetSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_set_revocations", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const revokeSetSchemaSQL = `CREATE TABLE @schema@.set_revocations(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose IN ('identity.session.revoke-other','identity.session.revoke-all')),
 user_id @schema@.scope_id NOT NULL,
 source_id @schema@.scope_id NOT NULL,
 before_version @schema@.version NOT NULL,
 after_version @schema@.version NOT NULL,
 subject_version @schema@.version NOT NULL,
 revoked_count integer NOT NULL CHECK(revoked_count BETWEEN 0 AND 100000),
 include_current boolean NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 result_digest bytea NOT NULL CHECK(octet_length(result_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(after_version=before_version+1),
 CHECK(NOT include_current OR revoked_count>0),
 CHECK(purpose='identity.session.revoke-all' OR NOT include_current)
);
CREATE INDEX session_owner_active_order ON @schema@.sessions(tenant_id,user_id,session_id) WHERE state='active';`
