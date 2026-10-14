package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// LockoutStateMigrationSource appends attributable transition storage without
// rewriting any installed interval or counter history. Allocate Version
// permanently after Base.Version. Existing restrictions retain their original
// versions, intervals and keyed roots; no command, authorization, transition or
// audit record is fabricated for them. Native start/end execution is separate
// from installing this schema, and interval-only admission remains unchanged.
type LockoutStateMigrationSource struct {
	Base    LockoutMigrationSource
	Version migrations.Version
}

var _ migrations.Source = LockoutStateMigrationSource{}

// Load returns owned complete forward-only atomic history. Nil/cancelled context
// and invalid version allocation fail before producing history. Concurrent
// calls are independent; there is no IO, backfill, reset or destructive down SQL.
func (s LockoutStateMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(lockoutStateSchemaSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_lockout_transitions", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, m), nil
}

// Ending preserves the original interval rather than deleting the CAS history
// or shortening expiry. Legacy rows have no claimed native custody. A native
// transition names an existing same-tenant command of the exact transition
// operation, with an opaque aggregate ID and complete binding digest. This is
// latest domain-state linkage, not another command/replay journal; historical
// outcomes remain owned by the identity coordinator.
const lockoutStateSchemaSQL = `ALTER TABLE @schema@.counter_lockouts
 ADD COLUMN record_id text COLLATE "C",
 ADD COLUMN ended_at timestamptz,
 ADD COLUMN command_id bytea,
 ADD COLUMN binding_digest bytea,
 ADD COLUMN command_operation text COLLATE "C",
 ADD CONSTRAINT risk_lockout_record CHECK(record_id IS NULL OR (record_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND record_id<>'AAAAAAAAAAAAAAAAAAAAAA')),
 ADD CONSTRAINT risk_lockout_end_time CHECK(ended_at IS NULL OR (isfinite(ended_at) AND ended_at>=started_at)),
 ADD CONSTRAINT risk_lockout_command CHECK(command_id IS NULL OR octet_length(command_id)=16),
 ADD CONSTRAINT risk_lockout_binding CHECK(binding_digest IS NULL OR octet_length(binding_digest)=32),
 ADD CONSTRAINT risk_lockout_transition CHECK(
  (record_id IS NULL AND ended_at IS NULL AND command_id IS NULL AND binding_digest IS NULL AND command_operation IS NULL)
  OR (record_id IS NOT NULL AND command_id IS NOT NULL AND binding_digest IS NOT NULL AND command_operation IS NOT NULL
   AND ((command_operation='identity.risk.start-lockout' AND ended_at IS NULL)
    OR (command_operation='identity.risk.end-lockout' AND ended_at IS NOT NULL)))),
 ADD CONSTRAINT risk_lockout_native_command FOREIGN KEY(command_id,tenant_id,command_operation)
  REFERENCES identity.commands(command_id,tenant_id,purpose);
CREATE UNIQUE INDEX risk_lockout_record_id ON @schema@.counter_lockouts(tenant_id,record_id) WHERE record_id IS NOT NULL;
`
