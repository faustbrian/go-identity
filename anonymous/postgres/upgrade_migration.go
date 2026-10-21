package anonymouspostgres

import (
	"context"
	"math"
	"strings"

	"github.com/faustbrian/go-identity/anonymous"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// UpgradeMigrationSource adds this owner's retained source/target merge journal
// after existing anonymous history. Existing SQL and deletion evidence stay
// unchanged. This finite profile transfers no resources: the only nonempty
// explicit decision is preserving profile.display_name on the permanent target.
// Kernel, password, MFA, capability and session histories remain independently
// required before the native upgrade can be selected. No endpoint is enabled.
type UpgradeMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only migration without IO. Version/schema are
// permanent explicit installation inputs; the existing runner owns ordering.
func (s UpgradeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, anonymous.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_anonymous_upgrades", migrations.TransactionModeDefault, strings.ReplaceAll(upgradeSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{m}, nil
}

const upgradeSQL = `CREATE TABLE @schema@.upgrades(
 tenant_id identity.directory_id NOT NULL,
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.anonymous.upgrade'),
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 user_id identity.directory_id NOT NULL,
 target_user_id identity.directory_id NOT NULL CHECK(target_user_id<>user_id),
 before_version identity.version NOT NULL,
 after_version identity.version NOT NULL CHECK(after_version=before_version+1),
 cleanup smallint NOT NULL CHECK(cleanup BETWEEN 1 AND 3),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>created_at),
 merge_fields text[] NOT NULL,
 merge_dispositions smallint[] NOT NULL,
 merge_digest bytea NOT NULL CHECK(octet_length(merge_digest)=32),
 CHECK(cardinality(merge_fields)<=1 AND cardinality(merge_fields)=cardinality(merge_dispositions)),
 CHECK(cardinality(merge_fields)=0 OR (array_ndims(merge_fields)=1 AND array_lower(merge_fields,1)=1 AND array_position(merge_fields,NULL) IS NULL)),
 CHECK(cardinality(merge_dispositions)=0 OR (array_ndims(merge_dispositions)=1 AND array_lower(merge_dispositions,1)=1 AND array_position(merge_dispositions,NULL) IS NULL)),
 CHECK(merge_fields<@ARRAY['profile.display_name']::text[] AND 2=ALL(merge_dispositions)),
 PRIMARY KEY(tenant_id,purpose,command_id),
 UNIQUE(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES @schema@.subjects(tenant_id,user_id),
 FOREIGN KEY(tenant_id,target_user_id) REFERENCES identity.users(tenant_id,user_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);`
