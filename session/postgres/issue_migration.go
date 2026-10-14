package postgres

import (
	"context"
	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
	"math"
	"strings"
)

// IssueMigrationSource appends immutable issuance evidence to the unchanged
// base/revocation history. Version is a permanent single-history allocation
// after Base.Version, at most MaxInt64. Kernel proof-use migrations must also be
// composed before protected issuance. Load performs no IO; no destructive down
// migration or payload cleanup is provided. Do not renumber applied versions.
type IssueMigrationSource struct {
	Base    RevocationMigrationSource
	Version migrations.Version
}

// Load returns independently owned history and the forward-only issuance table.
func (s IssueMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_migration"}
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(issueSchemaSQL, "@schema@", pgx.Identifier{s.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_issuances", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, m), nil
}

const issueSchemaSQL = `CREATE TABLE @schema@.session_issuances(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.session.issue'),
 user_id @schema@.scope_id NOT NULL,
 session_id @schema@.scope_id NOT NULL,
 family_id @schema@.scope_id NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 record_digest bytea NOT NULL CHECK(octet_length(record_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 UNIQUE(command_id),
 UNIQUE(tenant_id,session_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);`
