package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ProviderDisableCascadeMigrationSource installs the opt-in pending generation
// store after ProviderAuthorityMigrationSource in the same schema. The new
// empty table and its indexes do not rewrite or lock existing authority rows.
// Apply it before enabling ApplyDisableCascade on the provider operator.
type ProviderDisableCascadeMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = ProviderDisableCascadeMigrationSource{}

// Load returns a forward-only schema with no historical admission backfill.
func (s ProviderDisableCascadeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !providerAuthoritySchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_provider_disable_cascade_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(providerDisableCascadeSchemaSQL, "@schema@", rpQuotedSchema(s.Schema))
	migration, err := migrations.NewMigration(s.Version, "identity_oauth_provider_disable_cascade", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

// Hold state is inapplicable to this provider-owned admission. It does not
// waive user or organization retention rules on later consumer mutations.
const providerDisableCascadeSchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.provider_disable_cascades (
 tenant_id identity.directory_id NOT NULL,
 source_command_id text COLLATE "C" NOT NULL CHECK(source_command_id ~ '^[A-Za-z0-9_-]{22}$'),
 provider_id text COLLATE "C" NOT NULL CHECK(provider_id ~ '^[a-z0-9_-]{1,128}$'),
 actor_id identity.directory_id NOT NULL,
 previous_version identity.version NOT NULL,
 disabled_version identity.version NOT NULL CHECK(disabled_version>previous_version),
 profile_version identity.version NOT NULL,
 cascade_id text COLLATE "C" NOT NULL CHECK(cascade_id ~ '^[A-Za-z0-9_-]{22}$'),
 generation bigint NOT NULL CHECK(generation=1),
 manifest_version text COLLATE "C" NOT NULL CHECK(manifest_version='` + providerDisableCascadeManifest + `'),
 event_topic text COLLATE "C" NOT NULL CHECK(event_topic='` + providerDisableCascadeTopic + `'),
 event_version smallint NOT NULL CHECK(event_version=1),
 consumer_contracts jsonb NOT NULL CHECK(jsonb_typeof(consumer_contracts)='array' AND
  jsonb_array_length(consumer_contracts)=8 AND pg_column_size(consumer_contracts)<=2048),
 status smallint NOT NULL CHECK(status=1),
 legal_hold_state text COLLATE "C" NOT NULL CHECK(legal_hold_state='` + providerDisableCascadeHold + `'),
 admitted_at timestamptz NOT NULL CHECK(isfinite(admitted_at)),
 deadline_at timestamptz NOT NULL CHECK(isfinite(deadline_at) AND
  deadline_at>=admitted_at+interval '1 hour' AND deadline_at<=admitted_at+interval '720 hours'),
 PRIMARY KEY(tenant_id,source_command_id),
 UNIQUE(cascade_id),
 UNIQUE(provider_id,tenant_id,disabled_version)
);`
