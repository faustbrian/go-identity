package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// AnonymousDisposalMigrationSource appends retained session-owned deletion
// effect evidence after the installed session/anonymous histories. It enables
// no endpoint, changes no predecessor SQL and offers no destructive downgrade.
type AnonymousDisposalMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns a forward migration without IO; cancellation and invalid schema
// or version deny. The existing explicit migration runner owns installation.
func (s AnonymousDisposalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_anonymous_disposal_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_anonymous_session_disposals", migrations.TransactionModeDefault, strings.ReplaceAll(anonymousDisposalSessionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{m}, nil
}

const anonymousDisposalSessionSQL = `CREATE TABLE @schema@.anonymous_disposals(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.anonymous.delete'),
 user_id @schema@.scope_id NOT NULL,
 source_id @schema@.scope_id NOT NULL,
 before_version @schema@.version NOT NULL,
 after_version @schema@.version NOT NULL CHECK(after_version=before_version+1),
 revoked_count integer NOT NULL CHECK(revoked_count BETWEEN 1 AND 100000),
 family_count integer NOT NULL CHECK(family_count BETWEEN 1 AND 100000),
 effects_digest bytea NOT NULL CHECK(octet_length(effects_digest)=32),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 result_digest bytea NOT NULL CHECK(octet_length(result_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)
);`
