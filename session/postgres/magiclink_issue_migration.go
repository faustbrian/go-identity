package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MagicLinkSigninMigrationSource admits consuming email-grant signin in the
// existing retained session-issuance table after PasswordSignupMigrationSource.
// Allocate a permanent unused Version in the same owned schema. Existing rows,
// commitment domains and migration checksums are unchanged. No new replay store
// or destructive downgrade is introduced. Install before enabling this effect.
type MagicLinkSigninMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load constructs one bounded forward-only transactional constraint extension.
// The migration runner owns IO, locking and populated-state validation.
func (s MagicLinkSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_magiclink_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_magiclink_signin", migrations.TransactionModeDefault, strings.ReplaceAll(magicLinkSigninSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const magicLinkSigninSchemaSQL = `ALTER TABLE @schema@.session_issuances DROP CONSTRAINT session_issuances_purpose_v4;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_v5 CHECK(purpose IN('identity.session.issue','identity.otp.signin','identity.password.signin','identity.password.signup','identity.magic-link.consume'));
`
