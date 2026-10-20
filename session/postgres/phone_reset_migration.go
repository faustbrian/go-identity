package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PhonePasswordResetMigrationSource extends the existing all-session reset
// evidence purpose constraint. Install after PasswordResetMigrationSource in
// the same Schema and allocate Version after its installed history. Existing
// rows, migration checksums and effect digests remain unchanged. This suffix
// enables neither a recovery workflow nor independent revocation authority.
type PhonePasswordResetMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns forward transactional SQL without IO or destructive downgrade.
// Missing installed prerequisites fail when the existing runner applies it;
// nil/canceled contexts and invalid schema/version return no partial history.
func (s PhonePasswordResetMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_phone_password_reset_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_phone_password_reset_session_effects", migrations.TransactionModeDefault,
		strings.ReplaceAll(phonePasswordResetSessionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{forward}, nil
}

const phonePasswordResetSessionSQL = `ALTER TABLE @schema@.password_resets DROP CONSTRAINT password_resets_purpose_check;
ALTER TABLE @schema@.password_resets ADD CONSTRAINT password_resets_purpose_check CHECK(purpose IN ('identity.password.reset-complete','identity.phone.password-reset-complete'));
`
