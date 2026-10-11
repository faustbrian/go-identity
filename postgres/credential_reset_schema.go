package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// CredentialResetMigrationSource appends a forward-only reset extension to
// installed credential-replacement history. Existing migration bytes and
// password-change rows are unchanged. Install before selecting reset owners;
// old binaries remain change-only. Retained effects share command tombstone
// lifetime and do not store verifiers or bearers. Zero composition is invalid.
type CredentialResetMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns owned history without IO. Invalid/colliding versions return no
// partial history; cancellation is preserved. Destructive down SQL is absent.
func (s CredentialResetMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidCredentialReset()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidCredentialReset()
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalidCredentialReset()
		}
	}
	m, err := migrations.NewMigration(s.Version, "identity_credential_resets", migrations.TransactionModeDefault, credentialResetSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), m), nil
}

const credentialResetSQL = `ALTER TABLE identity.credential_replacements DROP CONSTRAINT credential_replacements_operation_check;
ALTER TABLE identity.credential_replacements ADD CONSTRAINT credential_replacements_operation_check CHECK (operation IN ('identity.password.change','identity.password.reset-complete'));
`
