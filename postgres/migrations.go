package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MigrationSource supplies this adapter's complete immutable forward-only
// history to go-migrations. The zero value is usable and concurrent-safe. Load
// performs no I/O, creates no ledger and does not execute SQL. Compose it with
// the owned migrations PostgreSQL backend and Runner, not a private runner.
// The initial atomic install requires an unoccupied identity schema; conflicting
// unmanaged objects fail rather than silently becoming owned tables.
type MigrationSource struct{}

var _ migrations.Source = MigrationSource{}

// Load returns independently owned migration values or no history on failure.
// A nonnil context is required; cancellation and deadline errors are preserved.
// Migrations never provide destructive down SQL. Use reviewed forward fixes.
func (MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil {
		return nil, identity.InvalidInputError{Field: "migration_context"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	migration, err := migrations.NewMigration(1, "identity_users", migrations.TransactionModeDefault, userSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	claims, err := migrations.NewMigration(2, "identity_command_claims", migrations.TransactionModeDefault, commandClaimSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	journal, err := migrations.NewMigration(3, "identity_command_leases", migrations.TransactionModeDefault, commandLeaseSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	terminal, err := migrations.NewMigration(4, "identity_command_results", migrations.TransactionModeDefault, commandTerminalSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration, claims, journal, terminal}, nil
}

// An unconstrained numeric plus integer/range checks rejects fractional input
// instead of rounding it before a CHECK, and preserves all uint64 values.
// C collation keeps stable bytewise ID equality independent of database locale.
const userSchemaSQL = `CREATE SCHEMA identity;

CREATE DOMAIN identity.directory_id AS text COLLATE "C"
 CHECK (octet_length(VALUE) BETWEEN 1 AND 128
        AND VALUE !~ '[[:cntrl:] ]');

CREATE DOMAIN identity.version AS numeric
 CHECK (VALUE >= 1 AND VALUE <= 18446744073709551615 AND scale(VALUE) = 0);

CREATE TABLE identity.users (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 status text COLLATE "C" NOT NULL
   CHECK (status IN ('active','suspended','banned','anonymized','deleted')),
 version identity.version NOT NULL,
 PRIMARY KEY (tenant_id,user_id)
);

CREATE INDEX identity_users_status_order ON identity.users(tenant_id,status,user_id);
`
