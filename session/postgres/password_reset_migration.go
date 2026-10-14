package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PasswordResetMigrationSource adds session-owned original reset-effect evidence
// after the installed session and kernel histories. Schema must match the store;
// allocate Version permanently. Existing migrations and change receipts remain
// unchanged. These rows are effect evidence, not another reset intent journal,
// and must remain with original command retention after live-session cleanup.
type PasswordResetMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns forward transactional SQL without IO. Nil/canceled contexts and
// invalid schema/version deny; the existing migration runner owns execution.
func (s PasswordResetMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_password_reset_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_password_reset_session_effects", migrations.TransactionModeDefault, strings.ReplaceAll(passwordResetSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const passwordResetSchemaSQL = `CREATE TABLE @schema@.password_resets(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.password.reset-complete'),
 user_id @schema@.scope_id NOT NULL,
 credential_id @schema@.scope_id NOT NULL,
 before_user_version @schema@.version NOT NULL CHECK(before_user_version<18446744073709551615),
 before_authority_version @schema@.version NOT NULL CHECK(before_authority_version<18446744073709551615),
 before_credential_version @schema@.version NOT NULL CHECK(before_credential_version<18446744073709551615),
 revoked_count integer NOT NULL CHECK(revoked_count BETWEEN 0 AND 100000),
 effects_digest bytea NOT NULL CHECK(octet_length(effects_digest)=32),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 result_digest bytea NOT NULL CHECK(octet_length(result_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)
);`
