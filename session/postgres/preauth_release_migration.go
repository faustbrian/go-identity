package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PreAuthReleaseMigrationSource adds distinct terminal noncommit state after
// PreAuthMigrationSource without modifying its applied checksum. Version is an
// allocated permanent slot in the sole history. The transactional constraint
// replacement scans existing rows and requires a bounded maintenance window.
// Original records, indexes and older state transitions remain unchanged.
// No destructive down migration is supplied.
type PreAuthReleaseMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load creates one forward transactional migration; invalid allocation and
// nil/canceled context deny before SQL generation. No IO runs here.
func (s PreAuthReleaseMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_preauth_release_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_preauth_release", migrations.TransactionModeDefault, strings.ReplaceAll(preAuthReleaseSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const preAuthReleaseSchemaSQL = `ALTER TABLE @schema@.preauth_transactions
 DROP CONSTRAINT preauth_transactions_state_check,
 DROP CONSTRAINT preauth_transactions_check1,
 ADD CONSTRAINT preauth_transactions_state_check CHECK(state IN('issued','reserved','consumed','released')),
 ADD CONSTRAINT preauth_transactions_check1 CHECK(
 (state='issued' AND version=issued_version AND command_id IS NULL AND fingerprint IS NULL AND generation IS NULL)
 OR (state IN('reserved','consumed','released') AND command_id IS NOT NULL AND fingerprint IS NOT NULL AND generation IS NOT NULL
 AND version=issued_version+CASE WHEN state='reserved' THEN 1 ELSE 2 END));
`
