package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// DurableCounterMigrationSource installs the PostgreSQL-only admission lane.
// It does not alter protected command counters or Valkey recovery history.
// Allocate Version once in the owning migration ledger. An existing selected
// risk schema may be shared; the five owned table names must not preexist.
type DurableCounterMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load is pure and cancellation-aware; all tables are created atomically by
// the native runner. There is no implicit historical counter reset or adoption.
func (s DurableCounterMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version < 1 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(durableCounterSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_durable_admission", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const durableCounterSQL = `CREATE SCHEMA IF NOT EXISTS @schema@;
CREATE TABLE @schema@.durable_counter_scopes(
 namespace text COLLATE "C" NOT NULL CHECK(namespace ~ '^[!-~]{1,128}$'),
 tenant_id text COLLATE "C" NOT NULL CHECK(tenant_id ~ '^[!-~]{1,128}$'),
 key_marker bytea NOT NULL CHECK(octet_length(key_marker)=32),
 records bigint NOT NULL DEFAULT 0 CHECK(records BETWEEN 0 AND 1000000),
 PRIMARY KEY(namespace,tenant_id)
);
CREATE TABLE @schema@.durable_counter_keys(
 namespace text COLLATE "C" NOT NULL, tenant_id text COLLATE "C" NOT NULL,
 operation text COLLATE "C" NOT NULL, phase text COLLATE "C" NOT NULL,
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 key_id text COLLATE "C" NOT NULL CHECK(length(key_id) BETWEEN 1 AND 64),
 PRIMARY KEY(namespace,tenant_id,operation,phase,key_version),
 FOREIGN KEY(namespace,tenant_id) REFERENCES @schema@.durable_counter_scopes
);
CREATE TABLE @schema@.durable_counter_windows(
 namespace text COLLATE "C" NOT NULL, tenant_id text COLLATE "C" NOT NULL,
 operation text COLLATE "C" NOT NULL, phase text COLLATE "C" NOT NULL,
 dimension text COLLATE "C" NOT NULL, root_key text COLLATE "C" NOT NULL,
 value numeric NOT NULL CHECK(value BETWEEN 1 AND 18446744073709551615 AND scale(value)=0),
 window_us bigint NOT NULL CHECK(window_us BETWEEN 1 AND 3600000000),
 started_at timestamptz NOT NULL CHECK(isfinite(started_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at-started_at=window_us*interval '1 microsecond'),
 PRIMARY KEY(namespace,tenant_id,operation,phase,dimension,root_key),
 FOREIGN KEY(namespace,tenant_id) REFERENCES @schema@.durable_counter_scopes
);
CREATE TABLE @schema@.durable_counter_aliases(
 namespace text COLLATE "C" NOT NULL, tenant_id text COLLATE "C" NOT NULL,
 operation text COLLATE "C" NOT NULL, phase text COLLATE "C" NOT NULL,
 dimension text COLLATE "C" NOT NULL, key_id text COLLATE "C" NOT NULL CHECK(length(key_id) BETWEEN 1 AND 64),
 root_key text COLLATE "C" NOT NULL,
 PRIMARY KEY(namespace,tenant_id,operation,phase,dimension,key_id),
 FOREIGN KEY(namespace,tenant_id,operation,phase,dimension,root_key) REFERENCES @schema@.durable_counter_windows
);
CREATE TABLE @schema@.durable_counter_attempts(
 namespace text COLLATE "C" NOT NULL, tenant_id text COLLATE "C" NOT NULL,
 attempt_digest bytea NOT NULL CHECK(octet_length(attempt_digest)=32),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 snapshots bytea NOT NULL CHECK(octet_length(snapshots) BETWEEN 1 AND 4096),
 seal bytea NOT NULL CHECK(octet_length(seal)=32),
 PRIMARY KEY(namespace,tenant_id,attempt_digest),
 FOREIGN KEY(namespace,tenant_id) REFERENCES @schema@.durable_counter_scopes
);`
