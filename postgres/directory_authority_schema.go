package postgres

import (
	"context"
	"math"
	"sort"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// DirectoryAuthorityMigrationSource installs independent global/tenant epochs
// through the owned forward-only migration history. Base must be nonnil; Version
// must exceed every installed base version and fit signed SQL migration storage.
// GlobalAuthorityID is one explicit deployment authority. TenantIDs declares
// 0..256 exact bootstrap tenants, never inferred from users or authentication.
// Initial epoch 1/active state is a trusted operator decision, not authentication
// evidence. Missing tenants remain denied, including users created by old code.
// Copying/reordering the same tenant set produces identical migration bytes.
// Do not mutate caller-owned fields concurrently with Load. Zero is invalid.
type DirectoryAuthorityMigrationSource struct {
	Base              migrations.Source
	Version           migrations.Version
	GlobalAuthorityID string
	TenantIDs         []identity.TenantID
}

var _ migrations.Source = DirectoryAuthorityMigrationSource{}

// Load supplies independently owned immutable install bytes and no destructive
// downgrade. Never change this configuration after its version is applied; new
// tenant onboarding and lifecycle mutations require their owned command APIs,
// not application-written SQL or edited historical migration checksums. Global
// compromise semantics and acknowledgement remain identity-owned and separate.
func (s DirectoryAuthorityMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "directory_authority_migration"}
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) || !queryScopeText(s.GlobalAuthorityID) || len(s.TenantIDs) > 256 {
		return nil, invalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tenants := make([]string, len(s.TenantIDs))
	for i, id := range s.TenantIDs {
		if !queryScopeText(string(id)) {
			return nil, invalid
		}
		tenants[i] = string(id)
	}
	sort.Strings(tenants)
	for i := 1; i < len(tenants); i++ {
		if tenants[i] == tenants[i-1] {
			return nil, invalid
		}
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalid
	}
	for _, migration := range history {
		if migration.Version() >= s.Version {
			return nil, invalid
		}
	}
	sql := directoryAuthoritySchemaSQL + "\nINSERT INTO identity.global_authorities(authority_id,version) VALUES(" + authoritySQLLiteral(s.GlobalAuthorityID) + ",1);\n"
	for _, id := range tenants {
		sql += "INSERT INTO identity.tenant_authorities(tenant_id,version,enabled) VALUES(" + authoritySQLLiteral(id) + ",1,true);\n"
	}
	forward, err := migrations.NewMigration(s.Version, "identity_directory_authority", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

// Escape strings independently of standard_conforming_strings. ID validation
// already bounds bytes and rejects controls; quotes/backslashes remain valid
// opaque IDs, not SQL syntax or a reason to silently normalize source identity.
func authoritySQLLiteral(id string) string {
	return "E'" + strings.ReplaceAll(strings.ReplaceAll(id, "\\", "\\\\"), "'", "''") + "'"
}

const directoryAuthoritySchemaSQL = `CREATE TABLE identity.global_authorities (
 authority_id identity.directory_id PRIMARY KEY,
 version identity.version NOT NULL
);
CREATE TABLE identity.tenant_authorities (
 tenant_id identity.directory_id PRIMARY KEY,
 version identity.version NOT NULL,
 enabled boolean NOT NULL
);
`
