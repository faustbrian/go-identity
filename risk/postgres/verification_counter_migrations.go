package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// VerificationCounterMigrationSource adds the distinct original-grant counter
// dimension to already installed protected counter history. Permanently allocate
// Version after every selected migration. Original migration bytes, populated
// windows, snapshots, aliases, charges and their times remain unchanged. This
// forward-only atomic migration neither resets allowance nor grants proof or
// transaction authority. Load is pure, bounded and concurrent-safe.
type VerificationCounterMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one owned forward migration; zero/invalid configuration denies,
// cancellation is preserved and missing/foreign installed constraints fail
// execution rather than silently adopting or rebuilding existing storage.
func (s VerificationCounterMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(verificationCounterSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_verification_counters", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const verificationCounterSQL = `ALTER TABLE @schema@.counter_windows
 DROP CONSTRAINT counter_windows_dimension_check,
 ADD CONSTRAINT counter_windows_dimension_check CHECK(dimension IN('tenant','subject','session','canonical_network','actor','target_or_resource') OR (dimension='capability' AND operation='identity.email.verification-confirm'));
ALTER TABLE @schema@.counter_snapshots
 DROP CONSTRAINT counter_snapshots_dimension_check,
 ADD CONSTRAINT counter_snapshots_dimension_check CHECK(dimension IN('tenant','subject','session','canonical_network','actor','target_or_resource','capability'));
`
