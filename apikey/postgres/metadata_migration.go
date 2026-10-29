package postgres

import (
	"context"
	"math"

	"github.com/faustbrian/go-identity/apikey"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MetadataMigrationSource adds self-owned metadata pagination after the native
// key history. It is opt-in: existing issuance/verification and exact-key Get
// do not require it. The partial index excludes organization-owned rows.
// Apply with bounded DDL/lock deadlines; the transactional index build blocks
// concurrent key writers until commit. A failed build must roll back before
// retry, never be replaced by IF NOT EXISTS against an unchecked index.
type MetadataMigrationSource struct{ Version migrations.Version }

func (s MetadataMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return metadataIndexMigration(ctx, s.Version, "identity_api_keys_metadata_user_page", metadataUserIndexSQL)
}

// OrganizationMetadataMigrationSource independently adds organization-owned
// paging after OrganizationMigrationSource. It does not require or enable the
// self-owned metadata extension. Only explicitly selected organization readers
// require this index; no organization schema is needed for self-only metadata.
// DDL locking and transactional rollback match MetadataMigrationSource.
type OrganizationMetadataMigrationSource struct{ Version migrations.Version }

func (s OrganizationMetadataMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return metadataIndexMigration(ctx, s.Version, "identity_api_keys_metadata_org_page", metadataOrganizationIndexSQL)
}

func metadataIndexMigration(ctx context.Context, version migrations.Version, name, sql string) ([]migrations.Migration, error) {
	if ctx == nil || version == 0 || version > migrations.Version(math.MaxInt64) {
		return nil, apikey.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(version, name, migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, apikey.ErrInvalid
	}
	return []migrations.Migration{step}, nil
}

// identity.directory_id already owns bytewise C collation. Equality prefixes
// provide an owner/configuration seek path; PostgreSQL still chooses the plan.
// Per-configuration limits bound result subsets, not physical rows examined.
const metadataUserIndexSQL = `CREATE INDEX identity_api_keys_metadata_user_page
 ON identity_api_keys.keys(tenant_id,user_id,configuration_id,key_id)
 WHERE user_id IS NOT NULL;`

const metadataOrganizationIndexSQL = `CREATE INDEX identity_api_keys_metadata_org_page
 ON identity_api_keys.keys(tenant_id,organization_id,configuration_id,key_id)
 WHERE organization_id IS NOT NULL;`
