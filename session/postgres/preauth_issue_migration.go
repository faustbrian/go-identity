package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PreAuthIssueMigrationSource installs retained native initiation evidence at
// a later permanent slot after the kernel and PreAuthMigrationSource histories.
// Evidence has no live-flow FK and must survive flow retirement. Apply through
// the sole migrations runner; it provides no destructive downgrade.
type PreAuthIssueMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load validates allocation and cancellation without IO and returns one atomic
// forward migration. Existing flow records and applied SQL remain unchanged.
func (s PreAuthIssueMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_preauth_issue_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(preAuthIssueSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_preauth_issuance", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const preAuthIssueSchemaSQL = `CREATE TABLE @schema@.preauth_issuances(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.session.preauth-issue'),
 flow_id @schema@.scope_id NOT NULL,
 record_digest bytea NOT NULL CHECK(octet_length(record_digest)=32),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 UNIQUE(tenant_id,flow_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)
);`
