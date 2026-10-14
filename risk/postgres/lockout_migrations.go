package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// LockoutMigrationSource appends durable restriction storage to the immutable
// protected-counter history. Restrictions name the same logical keyed root as
// retained counter aliases; neither rotation nor window reset creates a new
// restriction identity. Version is a permanent forward-only allocation after
// Base.Version. Installation creates no restriction and selects no trigger,
// duration or override. Production mutation commands remain separate work.
type LockoutMigrationSource struct {
	Base    CounterMigrationSource
	Version migrations.Version
}

var _ migrations.Source = LockoutMigrationSource{}

// Load returns owned complete atomic history, preserving prior migration bytes.
// Invalid allocation rejects before construction; cancellation is propagated.
func (s LockoutMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(lockoutSchemaSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_durable_lockouts", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, m), nil
}

const lockoutSchemaSQL = `CREATE TABLE @schema@.counter_lockouts(
 tenant_id text COLLATE "C" NOT NULL,
 operation text COLLATE "C" NOT NULL,
 dimension text COLLATE "C" NOT NULL,
 counter_id text COLLATE "C" NOT NULL,
 version numeric NOT NULL CHECK(version BETWEEN 1 AND 18446744073709551615 AND scale(version)=0),
 policy_version numeric NOT NULL CHECK(policy_version BETWEEN 1 AND 18446744073709551615 AND scale(policy_version)=0),
 started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>started_at),
 PRIMARY KEY(tenant_id,operation,dimension,counter_id),
 FOREIGN KEY(tenant_id,operation,dimension,counter_id) REFERENCES @schema@.counter_windows
);
CREATE INDEX risk_lockout_expiry ON @schema@.counter_lockouts(expires_at,tenant_id,operation,dimension,counter_id);
`
