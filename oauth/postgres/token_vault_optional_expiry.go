package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// TokenVaultOptionalExpiryMigrationSource adds honest absent access-token
// expiry to an installed TokenVaultMigrationSource table. Version and Version+1
// must be unused forward history allocations after that prerequisite. Load has
// no IO. Apply both phases with the existing migrations runner before enabling
// the GitHub profile. Existing rows, ciphertext/AAD and installed migration
// bytes remain unchanged; there is no backfill or destructive down migration.
// Old positive-expiry writers remain compatible with the expanded schema.
type TokenVaultOptionalExpiryMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = TokenVaultOptionalExpiryMigrationSource{}

// Load returns separate transactional expand and validation phases. Short
// lock_timeout bounds lock acquisition; validation does not take the table's
// write-blocking ACCESS EXCLUSIVE lock. A lock timeout is a failed migration,
// never permission to enable a profile before its schema is ready.
func (s TokenVaultOptionalExpiryMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !rpSchemaName(s.Schema) || s.Version == 0 || s.Version >= migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_token_vault_optional_expiry_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	statements := []struct{ name, sql string }{
		{"identity_oauth_token_vault_optional_expiry", rpTokenVaultOptionalExpirySchema},
		{"identity_oauth_token_vault_optional_expiry_validation", rpTokenVaultOptionalExpiryValidation},
	}
	history := make([]migrations.Migration, 0, len(statements))
	for index, statement := range statements {
		sql := strings.ReplaceAll(statement.sql, "@schema@", rpQuotedSchema(s.Schema))
		migration, err := migrations.NewMigration(s.Version+migrations.Version(index), statement.name, migrations.TransactionModeDefault, sql, "")
		if err != nil {
			return nil, identity.UnavailableError{}
		}
		history = append(history, migration)
	}
	return history, nil
}

// The old positive/range/nanosecond checks continue constraining every non-NULL
// pair. This new check prevents SQL's three-valued logic admitting a half-pair.
const rpTokenVaultOptionalExpirySchema = `SET LOCAL lock_timeout='5s';
ALTER TABLE @schema@.token_sets
 ALTER COLUMN access_expires_at_seconds DROP NOT NULL,
 ALTER COLUMN access_expires_at_nanoseconds DROP NOT NULL,
 ADD CONSTRAINT token_sets_optional_expiry_pair CHECK((access_expires_at_seconds IS NULL)=(access_expires_at_nanoseconds IS NULL)) NOT VALID;
`

const rpTokenVaultOptionalExpiryValidation = `SET LOCAL lock_timeout='5s';
ALTER TABLE @schema@.token_sets VALIDATE CONSTRAINT token_sets_optional_expiry_pair;
`
