package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ProxyDisablePairMigrationSource installs the optional frozen proxy selector
// store after ProviderDisableCascadeMigrationSource in the same schema. Apply
// it before enabling paired proxy disable admission. Source ownership is checked
// in the admission transaction and reread on acknowledgement, without a foreign
// key or a lock on an existing table. Only acknowledged_at is mutable.
type ProxyDisablePairMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = ProxyDisablePairMigrationSource{}

// Load returns one forward-only migration creating an empty pair store, with no
// backfill or change to existing provider admission rows.
func (s ProxyDisablePairMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !providerAuthoritySchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_proxy_disable_pair_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(proxyDisablePairSchemaSQL, "@schema@", rpQuotedSchema(s.Schema))
	migration, err := migrations.NewMigration(s.Version, "identity_oauth_proxy_disable_pair", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

const proxyDisablePairSchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.provider_disable_proxy_pairs (
 tenant_id identity.directory_id NOT NULL,
 source_command_id text COLLATE "C" NOT NULL CHECK(source_command_id ~ '^[A-Za-z0-9_-]{22}$'),
 cascade_id text COLLATE "C" NOT NULL CHECK(cascade_id ~ '^[A-Za-z0-9_-]{22}$'),
 generation bigint NOT NULL CHECK(generation>0),
 production_schema text COLLATE "C" NOT NULL CHECK(production_schema ~ '^[a-z][a-z0-9_]{0,62}$'
  AND production_schema NOT IN ('identity','public','audit','information_schema') AND production_schema !~ '^pg_'),
 preview_schema text COLLATE "C" NOT NULL CHECK(preview_schema ~ '^[a-z][a-z0-9_]{0,62}$'
  AND preview_schema NOT IN ('identity','public','audit','information_schema') AND preview_schema !~ '^pg_'),
 production_deployment text COLLATE "C" NOT NULL CHECK(production_deployment ~ '^[a-z0-9_-]{1,128}$'),
 preview_deployment text COLLATE "C" NOT NULL CHECK(preview_deployment ~ '^[a-z0-9_-]{1,128}$'
  AND preview_deployment<>production_deployment),
 acknowledged_at timestamptz CHECK(acknowledged_at IS NULL OR isfinite(acknowledged_at)),
 PRIMARY KEY(tenant_id,source_command_id)
);`
