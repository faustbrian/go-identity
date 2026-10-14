package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PasswordSignupMigrationSource admits signup in the existing retained issuance
// table after PasswordSigninMigrationSource. Allocate a permanent unused Version.
// Existing rows and commitments are unchanged; no second journal is introduced.
type PasswordSignupMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only transactional constraint extension without IO.
// The migration runner owns locking and populated-state validation.
func (s PasswordSignupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_password_signup_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_password_signup", migrations.TransactionModeDefault, strings.ReplaceAll(passwordSignupSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const passwordSignupSchemaSQL = `ALTER TABLE @schema@.session_issuances DROP CONSTRAINT session_issuances_purpose_v3;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_v4 CHECK(purpose IN('identity.session.issue','identity.otp.signin','identity.password.signin','identity.password.signup'));
`
