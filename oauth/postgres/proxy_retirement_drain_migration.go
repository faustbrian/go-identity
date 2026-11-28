package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ProxyRetirementDrainMigrationSource installs the optional local checkpoint
// store. It does not modify custody, issue grants or acknowledge an admission.
type ProxyRetirementDrainMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = ProxyRetirementDrainMigrationSource{}

// Load creates one empty table and its primary index, without a backfill.
func (s ProxyRetirementDrainMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !providerAuthoritySchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_proxy_retirement_drain_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(proxyRetirementDrainSchema, "@schema@", rpQuotedSchema(s.Schema))
	migration, err := migrations.NewMigration(s.Version, "identity_oauth_proxy_retirement_drain", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

const proxyRetirementDrainSchema = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.proxy_retirement_drains (
 tenant_id identity.directory_id NOT NULL,
 cascade_id text COLLATE "C" NOT NULL CHECK(cascade_id ~ '^[A-Za-z0-9_-]{22}$'),
 generation bigint NOT NULL CHECK(generation=1),
 role smallint NOT NULL CHECK(role IN (1,2)),
 deployment text COLLATE "C" NOT NULL CHECK(deployment ~ '^[a-z0-9_-]{1,128}$'),
 source_command_id text COLLATE "C" NOT NULL CHECK(source_command_id ~ '^[A-Za-z0-9_-]{22}$'),
 provider_id text COLLATE "C" NOT NULL CHECK(provider_id ~ '^[a-z0-9_-]{1,128}$'),
 source_version identity.version NOT NULL,
 revision bigint NOT NULL CHECK(revision>0),
 after_flow_id text COLLATE "C" NOT NULL CHECK(after_flow_id='' OR after_flow_id ~ '^[A-Za-z0-9_-]{22}$'),
 pending_page jsonb CHECK(jsonb_typeof(pending_page)='object' AND octet_length(pending_page::text)<=8192
  AND pending_page ? 'next' AND jsonb_typeof(pending_page->'next')='string'
  AND pending_page ? 'targets' AND jsonb_typeof(pending_page->'targets')='array'),
 confirmed smallint NOT NULL CHECK(confirmed BETWEEN 0 AND 32),
 retired bigint NOT NULL CHECK(retired>=0),
 exhausted boolean NOT NULL,
 CHECK(pending_page IS NOT NULL OR confirmed=0),
 CHECK(NOT exhausted OR pending_page IS NULL),
 PRIMARY KEY(tenant_id,cascade_id,generation,role,deployment)
);`
