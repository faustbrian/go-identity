package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PasswordChangeMigrationSource adds retained session-owned effect evidence to
// the existing migration history. Schema must match the installed session store;
// allocate Version permanently after credential-continuation and kernel
// credential-replacement histories. Existing rows/checksums remain unchanged.
// Evidence belongs to original command retention, not live session payloads;
// no session FK or destructive down migration is provided. Load performs no IO.
type PasswordChangeMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns independently owned transactional forward SQL. The sole runner
// owns execution and commit. Nil/canceled context and invalid ownership deny
// without partial history. Concurrent immutable calls are safe.
func (s PasswordChangeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_password_change_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_password_session_effects", migrations.TransactionModeDefault, strings.ReplaceAll(passwordChangeSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const passwordChangeSchemaSQL = `CREATE TABLE @schema@.password_changes(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.password.change'),
 user_id @schema@.scope_id NOT NULL,
 credential_id @schema@.scope_id NOT NULL,
 source_id @schema@.scope_id NOT NULL,
 source_version @schema@.version NOT NULL,
 disposition smallint NOT NULL CHECK(disposition BETWEEN 1 AND 3),
 maximum_sessions integer NOT NULL CHECK(maximum_sessions BETWEEN 1 AND 100000),
 before_user_version @schema@.version NOT NULL CHECK(before_user_version<18446744073709551615),
 before_authority_version @schema@.version NOT NULL CHECK(before_authority_version<18446744073709551615),
 before_credential_version @schema@.version NOT NULL CHECK(before_credential_version<18446744073709551615),
 preserved_count integer NOT NULL CHECK(preserved_count BETWEEN 0 AND 100000),
 revoked_count integer NOT NULL CHECK(revoked_count BETWEEN 0 AND 100000),
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 effects_digest bytea NOT NULL CHECK(octet_length(effects_digest)=32),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 result_digest bytea NOT NULL CHECK(octet_length(result_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(preserved_count+revoked_count BETWEEN 1 AND maximum_sessions),
 CHECK(disposition<>1 OR preserved_count>=1),
 CHECK(disposition<>2 OR preserved_count=1),
 CHECK(disposition<>3 OR preserved_count=0)
);`
