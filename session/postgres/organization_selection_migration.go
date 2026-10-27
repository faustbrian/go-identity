package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// OrganizationSelectionMigrationSource adds session-owned immutable CAS
// evidence for the organization's existing command journal. It creates no
// alternate command/retry authority or selection store. Source/successor omit
// raw credentials; retained evidence survives ordinary session payload cleanup.
// Allocate Version permanently after the existing session history. No old SQL
// checksum, payload, family or digest index changes; no downgrade is supplied.
type OrganizationSelectionMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load validates scope/version/cancellation and returns owned forward-only SQL
// without IO. Install through the existing sole migration runner before enabling
// selection. The identity command and session scalar domains must already exist.
func (s OrganizationSelectionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_organization_selection_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(organizationSelectionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_organization_selections", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{m}, nil
}

const organizationSelectionSQL = `CREATE TABLE @schema@.organization_selections(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.organization.active-set'),
 user_id @schema@.scope_id NOT NULL,
 session_id @schema@.scope_id NOT NULL,
 before_version @schema@.version NOT NULL,
 after_version @schema@.version NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 successor_digest bytea NOT NULL CHECK(octet_length(successor_digest)=32),
 source_record jsonb NOT NULL CHECK(jsonb_typeof(source_record)='object' AND octet_length(source_record::text)<=32768),
 successor_record jsonb NOT NULL CHECK(jsonb_typeof(successor_record)='object' AND octet_length(successor_record::text)<=32768),
 PRIMARY KEY(tenant_id,command_id),
 UNIQUE(tenant_id,session_id,before_version),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(after_version=before_version+1)
);
`
