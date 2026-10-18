package passwordpostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// UsernameMFAMigrationSource extends the non-final password comparison store
// with the distinct username action. Allocate Version after Base; existing
// migration checksums, signed password records and original commands remain
// unchanged. No challenge or authentication is backfilled by this suffix.
type UsernameMFAMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load copies the selected forward-only history without database access.
// Base must be nonempty and Version must follow every installed predecessor.
func (s UsernameMFAMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (UsernameSigninMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_password_username_mfa", migrations.TransactionModeDefault, `ALTER TABLE identity_password.mfa_primary_records
 DROP CONSTRAINT mfa_primary_records_purpose_check,
 ADD CONSTRAINT mfa_primary_records_purpose_v2 CHECK(purpose IN('identity.password.signin','identity.username.signin'));
`, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}
