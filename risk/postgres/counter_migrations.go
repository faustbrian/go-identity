package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// CounterMigrationSource appends protected fixed-window counters and immutable
// command-linked snapshots after the existing evidence history. Allocate Version
// permanently after Base.Version. Existing evidence SQL is unchanged; Load is
// pure/concurrent-safe and returns owned forward-only atomic history. Key history
// is append-only: this profile does not yet authorize key retirement or pruning.
type CounterMigrationSource struct {
	Base    ReservationMigrationSource
	Version migrations.Version
}

var _ migrations.Source = CounterMigrationSource{}

// Load returns owned complete forward history; invalid allocation is redacted
// and cancellation is preserved before any SQL construction.
func (s CounterMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	history, e := s.Base.Load(ctx)
	if e != nil {
		return nil, e
	}
	sql := strings.ReplaceAll(counterSchemaSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Schema}.Sanitize())
	m, e := migrations.NewMigration(s.Version, "identity_risk_protected_counters", migrations.TransactionModeDefault, sql, "")
	if e != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, m), nil
}

const counterSchemaSQL = `CREATE TABLE @schema@.counter_key_history(
 tenant_id text COLLATE "C" NOT NULL CHECK(tenant_id ~ '^[!-~]{1,128}$'),
 operation text COLLATE "C" NOT NULL CHECK(length(operation) BETWEEN 1 AND 128),
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 tenant_key text COLLATE "C" NOT NULL CHECK(tenant_key ~ '^rc1:[1-9][0-9]{0,9}:[A-Za-z0-9_-]{43}$'),
 PRIMARY KEY(tenant_id,operation,key_version),UNIQUE(tenant_id,operation,tenant_key)
);
CREATE TABLE @schema@.counter_windows(
 tenant_id text COLLATE "C" NOT NULL,
 operation text COLLATE "C" NOT NULL,
 dimension text COLLATE "C" NOT NULL CHECK(dimension IN('tenant','subject','session','canonical_network','actor','target_or_resource')),
 counter_id text COLLATE "C" NOT NULL CHECK(counter_id ~ '^rc1:[1-9][0-9]{0,9}:[A-Za-z0-9_-]{43}$'),
 value numeric NOT NULL CHECK(value>=0 AND value<=18446744073709551615 AND scale(value)=0),
 window_us bigint NOT NULL CHECK(window_us BETWEEN 1 AND 3600000000),
 started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>started_at),
 PRIMARY KEY(tenant_id,operation,dimension,counter_id),
 CHECK(expires_at-started_at=window_us*interval '1 microsecond')
);
CREATE TABLE @schema@.counter_aliases(
 tenant_id text COLLATE "C" NOT NULL,operation text COLLATE "C" NOT NULL,dimension text COLLATE "C" NOT NULL,
 key_version bigint NOT NULL,key_id text COLLATE "C" NOT NULL CHECK(key_id ~ '^rc1:[1-9][0-9]{0,9}:[A-Za-z0-9_-]{43}$'),
 counter_id text COLLATE "C" NOT NULL,
 PRIMARY KEY(tenant_id,operation,dimension,key_version,key_id),
 FOREIGN KEY(tenant_id,operation,key_version) REFERENCES @schema@.counter_key_history,
 FOREIGN KEY(tenant_id,operation,dimension,counter_id) REFERENCES @schema@.counter_windows
);
CREATE TABLE @schema@.counter_charges(
 command_id bytea PRIMARY KEY CHECK(octet_length(command_id)=16),
 tenant_id text COLLATE "C" NOT NULL,operation text COLLATE "C" NOT NULL,
 command_fingerprint bytea NOT NULL CHECK(octet_length(command_fingerprint)=32),
 counter_fingerprint bytea NOT NULL CHECK(octet_length(counter_fingerprint)=32),
 policy_version numeric NOT NULL CHECK(policy_version BETWEEN 1 AND 18446744073709551615 AND scale(policy_version)=0),
 generation numeric NOT NULL CHECK(generation BETWEEN 1 AND 18446744073709551615 AND scale(generation)=0),
 allowed boolean NOT NULL,
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at)),
 prepared_at timestamptz NOT NULL CHECK(isfinite(prepared_at) AND prepared_at<=observed_at),
 FOREIGN KEY(command_id,tenant_id,operation) REFERENCES identity.commands(command_id,tenant_id,purpose)
);
CREATE TABLE @schema@.counter_snapshots(
 command_id bytea NOT NULL REFERENCES @schema@.counter_charges,
 dimension text COLLATE "C" NOT NULL CHECK(dimension IN('tenant','subject','session','canonical_network','actor','target_or_resource')),
 value numeric NOT NULL CHECK(value BETWEEN 1 AND 18446744073709551615 AND scale(value)=0),
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at)),
 started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>started_at),
 PRIMARY KEY(command_id,dimension),CHECK(observed_at>=started_at AND observed_at<expires_at)
);
CREATE INDEX risk_counter_expiry ON @schema@.counter_windows(expires_at,tenant_id,operation,dimension,counter_id);
CREATE INDEX risk_counter_charge_scope ON @schema@.counter_charges(tenant_id,operation,command_id);
`
