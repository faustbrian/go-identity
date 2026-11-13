package postgres

import (
	"context"
	"math"

	"github.com/faustbrian/go-identity/apikey"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// QuotaMigrationSource installs optional bucket state after the base key schema.
// Install it before enabling QuotaTokenBucket. Existing unlimited/legacy code
// never reads this table. It creates only a new table/primary index, touches no
// existing rows, and requires no backfill or existing-key-table lock. Reverting
// quota-aware code preserves unused state; no destructive down step is supplied.
type QuotaMigrationSource struct{ Version migrations.Version }

func (s QuotaMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, apikey.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_api_key_token_buckets", migrations.TransactionModeDefault, quotaSQL, "")
	if err != nil {
		return nil, apikey.ErrInvalid
	}
	return []migrations.Migration{step}, nil
}

// Balance is an exact integer numerator: one token costs interval microseconds.
// 1e6 capacity * MaxInt64 nanoseconds / 1000 fits the stated bound. numeric(39,0)
// also holds the intermediate product of uint64 refill amount and any finite
// PostgreSQL timestamp difference in microseconds, without floating conversion.
// No FK couples this observation state to key-row removal or command evidence.
const quotaSQL = `CREATE TABLE identity_api_keys.quotas(
 tenant_id identity.directory_id NOT NULL,
 configuration_id identity.directory_id NOT NULL,
 key_id identity.directory_id NOT NULL,
 capacity_units numeric(39,0) NOT NULL CHECK(capacity_units BETWEEN 1 AND 9223372036854775000000),
 balance numeric(39,0) NOT NULL CHECK(balance>=0 AND balance<=capacity_units),
 observed_at timestamptz NOT NULL CHECK(isfinite(observed_at)),
 PRIMARY KEY(tenant_id,configuration_id,key_id)
);`
