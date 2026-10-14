package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// PasswordContinuationMigrationSource extends the installed continuation
// history to genuine password-first challenges. Allocate Version after Base;
// existing migration bytes and original pending/terminal records stay unchanged.
// No primary is backfilled and no attempts or expiry are reset.
type PasswordContinuationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns a forward-only constraint extension without accessing a database.
// Missing, empty or misordered Base histories deny as with other MFA extensions.
func (s PasswordContinuationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (ContinuationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_password_continuations", migrations.TransactionModeDefault, passwordContinuationSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

const passwordContinuationSQL = `ALTER TABLE identity_mfa.continuations
 DROP CONSTRAINT continuations_origin_purpose_check,
 ADD CONSTRAINT continuations_origin_purpose_check CHECK(origin_purpose IN('identity.magic-link.consume','identity.password.signin'));
`
