package postgres

import (
	"context"
	"math"

	"github.com/faustbrian/go-identity/apikey"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// OrganizationMigrationSource optionally adds explicit organization key ownership
// after the existing key and organization histories. Existing user rows and old
// migration checksums remain unchanged. The owning runner must bound DDL locks;
// dropping this extension after organization issuance is not a safe downgrade.
type OrganizationMigrationSource struct{ Version migrations.Version }

func (s OrganizationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, apikey.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_api_keys_organization_owner", migrations.TransactionModeDefault, organizationOwnerSQL, "")
	if err != nil {
		return nil, apikey.ErrInvalid
	}
	return []migrations.Migration{step}, nil
}

// SI-08: ownership cannot retain the creator's user foreign key. The tagged
// owner is enforced on the key row; existing user writers still supply exactly
// their original columns, while organization writers require this extension.
const organizationOwnerSQL = `ALTER TABLE identity_api_keys.keys
 ALTER COLUMN user_id DROP NOT NULL,
 ADD COLUMN organization_id identity.directory_id,
 ADD CONSTRAINT identity_api_keys_exact_owner
  CHECK ((user_id IS NULL) <> (organization_id IS NULL)),
 ADD CONSTRAINT identity_api_keys_organization_owner
  FOREIGN KEY(tenant_id,organization_id)
  REFERENCES organization.organizations(tenant_id,organization_id);`
