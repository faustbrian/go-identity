package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFACompletionCounterMigrationSource adds the original child capability
// dimension for anonymous native TOTP completion after protected and registration
// verification counter histories. Allocate Version once after every selected
// predecessor. Existing windows, charges, aliases, snapshots and key/timing
// evidence remain unchanged. The atomic forward migration grants no allowance
// or proof authority and admits no other new capability-scoped operation.
type MFACompletionCounterMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load is pure, bounded and concurrent-safe, returning one owned forward
// migration. Invalid inputs/cancellation fail without SQL; execution requires
// the owned predecessor tables and constraints rather than rebuilding them.
func (s MFACompletionCounterMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(mfaCompletionCounterSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_mfa_completion_counters", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const mfaCompletionCounterSQL = `ALTER TABLE @schema@.counter_windows
 DROP CONSTRAINT counter_windows_dimension_check,
 ADD CONSTRAINT counter_windows_dimension_check CHECK(dimension IN('tenant','subject','session','canonical_network','actor','target_or_resource') OR (dimension='capability' AND operation IN('identity.email.verification-confirm','identity.mfa.totp-verify')));
`
