package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhonePasswordResetMigrationSource appends the exact phone-reset operation to
// the canonical credential replacement receipt constraint. Base must include
// CredentialResetMigrationSource; allocate Version after its installed history.
// All predecessor SQL/checksums and existing password-change/email-reset rows
// stay unchanged. This enables no recovery workflow or new storage authority.
type PhonePasswordResetMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns forward transactional history without IO or destructive down
// SQL. Nil/canceled input, empty history and version collisions return no partial
// history. The existing migration runner owns application and replay.
func (s PhonePasswordResetMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	m, err := migrations.NewMigration(s.Version, "identity_phone_password_resets", migrations.TransactionModeDefault, phonePasswordResetSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), m), nil
}

const phonePasswordResetSQL = `ALTER TABLE identity.credential_replacements DROP CONSTRAINT credential_replacements_operation_check;
ALTER TABLE identity.credential_replacements ADD CONSTRAINT credential_replacements_operation_check CHECK (operation IN ('identity.password.change','identity.password.reset-complete','identity.phone.password-reset-complete'));
`
