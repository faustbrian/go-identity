package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFALoginSendCounterMigrationSource adds the original browser-flow dimension
// after the selected protected, registration and MFA completion histories.
// Allocate Version permanently after those predecessors. Populated windows,
// aliases, charges, key history and original snapshot times remain unchanged.
// The forward-only atomic migration enables storage, not source authentication
// or allowance; native registered MFA/counter owners remain mandatory.
type MFALoginSendCounterMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one owned forward migration without IO. Invalid schema/version,
// nil context and cancellation fail before SQL construction. Concurrent calls
// are safe; missing predecessor constraints fail execution without rebuilding
// tables or silently adopting another storage profile.
func (s MFALoginSendCounterMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(mfaLoginSendCounterSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_mfa_login_send_counters", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const mfaLoginSendCounterSQL = `ALTER TABLE @schema@.counter_windows
 DROP CONSTRAINT counter_windows_dimension_check,
 ADD CONSTRAINT counter_windows_dimension_check CHECK(dimension IN('tenant','subject','session','canonical_network','actor','target_or_resource') OR (dimension='capability' AND operation IN('identity.email.verification-confirm','identity.mfa.totp-verify','identity.mfa.recovery-use')) OR (dimension='browser-flow' AND operation='identity.mfa.otp-send'));
ALTER TABLE @schema@.counter_snapshots
 DROP CONSTRAINT counter_snapshots_dimension_check,
 ADD CONSTRAINT counter_snapshots_dimension_check CHECK(dimension IN('tenant','subject','session','canonical_network','actor','target_or_resource','capability','browser-flow'));
`
