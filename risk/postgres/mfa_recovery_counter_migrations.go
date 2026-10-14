package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFARecoveryCounterMigrationSource extends the existing completion-counter
// history with recovery-code completion. Allocate Version after that history.
// Existing windows, charges and their original timing remain unchanged; this
// migration grants neither allowance nor authentication authority.
type MFARecoveryCounterMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward migration without IO. Cancellation and invalid
// schema/version fail before SQL construction. Concurrent calls are safe.
func (s MFARecoveryCounterMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(mfaRecoveryCounterSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_mfa_recovery_counters", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const mfaRecoveryCounterSQL = `ALTER TABLE @schema@.counter_windows
 DROP CONSTRAINT counter_windows_dimension_check,
 ADD CONSTRAINT counter_windows_dimension_check CHECK(dimension IN('tenant','subject','session','canonical_network','actor','target_or_resource') OR (dimension='capability' AND operation IN('identity.email.verification-confirm','identity.mfa.totp-verify','identity.mfa.recovery-use')));
`
