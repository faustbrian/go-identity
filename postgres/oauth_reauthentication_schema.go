package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// OAuthReauthenticationMigrationSource appends the closed OAuth age-expiry
// terminal classification after installed terminal/preparation history. Prior
// migration bytes, receipts and all existing shape checks remain unchanged.
// Apply before selecting fresh-login continuation handoff, using readers that
// understand OAuthReauthenticationRequiredError. It adds no retry/outcome store
// or new command lifecycle and has no destructive down migration.
type OAuthReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns owned forward history without IO. Missing base, empty history,
// out-of-order/colliding versions and cancellation return no partial history.
func (s OAuthReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidPreparation()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidPreparation()
	}
	for _, migration := range history {
		if migration.Version() >= s.Version {
			return nil, invalidPreparation()
		}
	}
	migration, err := migrations.NewMigration(s.Version, "identity_oauth_reauthentication", migrations.TransactionModeDefault, oauthReauthenticationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), migration), nil
}

const oauthReauthenticationSQL = `ALTER TABLE identity.commands
 DROP CONSTRAINT identity_command_terminal_shape,
 ADD CONSTRAINT identity_command_terminal_shape CHECK (
 ((state IS NULL OR state='pending') AND num_nonnulls(result_version,terminal_class,result,terminal_at)=0)
 OR (state IS NOT NULL AND state IN ('committed','aborted') AND num_nonnulls(result_version,terminal_class,result,terminal_at)=4
 AND result_version=1 AND octet_length(result) BETWEEN 1 AND 8388608
 AND isfinite(terminal_at) AND created_at<=terminal_at AND terminal_at=updated_at
 AND ((state='committed' AND terminal_class='committed')
 OR (state='aborted' AND terminal_class IN ('denied','conflict','cancelled','deadline-exceeded','dependency-failure','reauthentication-required')))));
`
