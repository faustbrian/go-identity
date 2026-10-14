package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFAOTPCompletionCounterMigrationSource selects original-child OTP completion
// after protected, verification, MFA completion/recovery and login-send counter
// histories. Allocate Version once after every selected predecessor. Existing
// windows, aliases, charges, snapshots, keys and evidence deadlines are unchanged.
// Storage support grants no allowance: both actual MFA and OTP owners remain
// mandatory, and browser-flow scope stays exclusive to OTP sending.
type MFAOTPCompletionCounterMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one owned forward migration without IO. Missing predecessor
// constraints fail execution; nil context, cancellation and invalid schema or
// version fail before SQL construction. Concurrent calls are safe.
func (s MFAOTPCompletionCounterMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(mfaOTPCompletionCounterSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_mfa_otp_completion_counters", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const mfaOTPCompletionCounterSQL = `ALTER TABLE @schema@.counter_windows
 DROP CONSTRAINT counter_windows_dimension_check,
 ADD CONSTRAINT counter_windows_dimension_check CHECK(dimension IN('tenant','subject','session','canonical_network','actor','target_or_resource') OR (dimension='capability' AND operation IN('identity.email.verification-confirm','identity.mfa.totp-verify','identity.mfa.recovery-use','identity.mfa.otp-verify')) OR (dimension='browser-flow' AND operation='identity.mfa.otp-send'));
`
