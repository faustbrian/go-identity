package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ProviderAuthorityMigrationSource installs the generic social-provider
// authority in an existing OAuth schema. Apply after MigrationSource and
// before enabling live connection authority. Existing providers need explicit
// trusted registration; an absent row never conveys authority. There is no
// backfill, rewrite of existing tables, or destructive downgrade.
type ProviderAuthorityMigrationSource struct {
	Schema  string
	Version migrations.Version
}

func (s ProviderAuthorityMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !providerAuthoritySchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, providerAuthorityInvalid()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(providerAuthoritySchemaSQL, "@schema@", rpQuotedSchema(s.Schema))
	step, err := migrations.NewMigration(s.Version, "identity_oauth_provider_authority", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{step}, nil
}

func providerAuthoritySchema(schema string) bool { return schema != "audit" && rpSchemaName(schema) }

const providerAuthoritySchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.provider_authorities (
 tenant_id identity.directory_id NOT NULL,
 provider_id text COLLATE "C" NOT NULL CHECK(provider_id ~ '^[a-z0-9_-]{1,128}$'),
 version identity.version NOT NULL,
 profile_version identity.version NOT NULL,
 enabled boolean NOT NULL,
 previous_version numeric NOT NULL CHECK(scale(previous_version)=0 AND previous_version>=0 AND previous_version<version),
 command_id text COLLATE "C" NOT NULL CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$'),
 command_actor identity.directory_id NOT NULL,
 PRIMARY KEY(tenant_id,provider_id)
);`
