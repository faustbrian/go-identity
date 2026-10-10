package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PasswordSignupAcceptanceMigrationSource appends the optional anonymous signup
// branch to existing registration evidence. Base must include the immutable
// PasswordRegistrationMigrationSource history. Version follows every base
// migration. Existing creation receipts and all old migration bytes remain
// unchanged. Apply with the migrations Runner; Load performs no database IO.
// Old readers fail closed on the new NULL subject arm rather than selecting an
// existing account. There is no destructive downgrade or historical inference.
type PasswordSignupAcceptanceMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independently owned forward-only history. Cancellation wins;
// missing base, out-of-order versions and malformed history deny before SQL.
func (s PasswordSignupAcceptanceMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidPasswordRegistration()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidPasswordRegistration()
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalidPasswordRegistration()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_password_signup_acceptance", migrations.TransactionModeDefault, signupAcceptanceSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const signupAcceptanceSchemaSQL = `ALTER TABLE identity.registration_bindings
 ADD COLUMN accepted_only boolean NOT NULL DEFAULT false,
 ALTER COLUMN user_id DROP NOT NULL,
 ALTER COLUMN identifier_id DROP NOT NULL,
 ALTER COLUMN credential_id DROP NOT NULL,
 ADD CONSTRAINT identity_registration_disposition CHECK (
  (accepted_only AND user_id IS NULL AND identifier_id IS NULL AND credential_id IS NULL)
  OR (NOT accepted_only AND user_id IS NOT NULL AND identifier_id IS NOT NULL AND credential_id IS NOT NULL)
 );
`

var _ migrations.Source = PasswordSignupAcceptanceMigrationSource{}
