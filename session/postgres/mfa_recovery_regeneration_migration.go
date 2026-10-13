package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFARecoverySessionMigrationSource installs retained original whole-set
// session disposition evidence. Schema must match the selected session store.
// Allocate Version permanently in the selected physical history; no populated
// session row is changed or backfilled. Original effect evidence remains after
// session payload cleanup and follows protected command-retention ownership.
type MFARecoverySessionMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns independently owned forward-only transactional SQL without IO.
// Invalid ownership, nil/canceled context and version overflow return no history.
func (s MFARecoverySessionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_mfa_recovery_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_mfa_recovery_session_effects", migrations.TransactionModeDefault, strings.ReplaceAll(mfaRecoveryDispositionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const mfaRecoveryDispositionSQL = `CREATE TABLE @schema@.mfa_recovery_dispositions(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.mfa.recovery-regenerate'),
 user_id @schema@.scope_id NOT NULL,
 source_session_id @schema@.scope_id NOT NULL,
 source_session_version @schema@.version NOT NULL,
 source_digest bytea NOT NULL CHECK(octet_length(source_digest)=32),
 before_factor_version @schema@.version NOT NULL CHECK(before_factor_version<18446744073709551615),
 after_factor_version @schema@.version NOT NULL CHECK(after_factor_version=before_factor_version+1),
 revoked_count integer NOT NULL CHECK(revoked_count BETWEEN 1 AND 1024),
 effects_digest bytea NOT NULL CHECK(octet_length(effects_digest)=32),
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 result_digest bytea NOT NULL CHECK(octet_length(result_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)
);`
