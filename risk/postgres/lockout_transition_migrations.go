package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// LockoutTransitionMigrationSource appends immutable domain-version evidence
// after LockoutStateMigrationSource. Version is a permanent unique forward
// allocation. Original intervals, history and legacy custody are untouched;
// no successful transition is backfilled. Historical command outcomes remain
// coordinator-owned. Domain versions must be retained while referenced by any
// unresolved or retained command; this profile does not expose pruning.
type LockoutTransitionMigrationSource struct {
	Base    LockoutStateMigrationSource
	Version migrations.Version
}

var _ migrations.Source = LockoutTransitionMigrationSource{}

// Load returns independent atomic forward-only history without IO or down SQL.
func (s LockoutTransitionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	history, e := s.Base.Load(ctx)
	if e != nil {
		return nil, e
	}
	sql := strings.ReplaceAll(lockoutTransitionSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Base.Base.Schema}.Sanitize())
	m, e := migrations.NewMigration(s.Version, "identity_risk_lockout_domain_versions", migrations.TransactionModeDefault, sql, "")
	if e != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, m), nil
}

const lockoutTransitionSQL = `CREATE TABLE @schema@.lockout_transitions(
 command_id bytea PRIMARY KEY CHECK(octet_length(command_id)=16),
 tenant_id text COLLATE "C" NOT NULL,
 command_operation text COLLATE "C" NOT NULL,
 record_id text COLLATE "C" NOT NULL CHECK(record_id ~ '^[A-Za-z0-9_-]{21}[AQgw]$' AND record_id<>'AAAAAAAAAAAAAAAAAAAAAA'),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
 signing_version bigint NOT NULL CHECK(signing_version BETWEEN 1 AND 4294967295),
 authority_version numeric NOT NULL CHECK(authority_version BETWEEN 1 AND 18446744073709551615 AND scale(authority_version)=0),
 before_version numeric NOT NULL CHECK(before_version BETWEEN 0 AND 18446744073709551614 AND scale(before_version)=0),
 after_version numeric NOT NULL CHECK(after_version=before_version+1),
 operation text COLLATE "C" NOT NULL,
 counter_id text COLLATE "C" NOT NULL,
 policy_version numeric NOT NULL CHECK(policy_version BETWEEN 1 AND 18446744073709551615 AND scale(policy_version)=0),
 started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>started_at),
 ended_at timestamptz CHECK(ended_at IS NULL OR (isfinite(ended_at) AND ended_at>=started_at)),
 UNIQUE(tenant_id,record_id,after_version),
 FOREIGN KEY(command_id,tenant_id,command_operation) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK((command_operation='identity.risk.start-lockout' AND ended_at IS NULL) OR (command_operation='identity.risk.end-lockout' AND ended_at IS NOT NULL))
);
`
