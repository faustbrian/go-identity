package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PasswordSigninMigrationSource admits password signin in the existing retained
// issuance table. Install after OTPIssueMigrationSource in the same owned schema,
// using a permanent unused Version. Existing rows and digest bytes are unchanged;
// no second journal, authority or destructive downgrade is introduced.
type PasswordSigninMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load constructs one bounded forward-only transactional constraint extension.
// The migration runner owns IO, table locking and populated-state validation.
func (s PasswordSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_password_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_password_signin", migrations.TransactionModeDefault, strings.ReplaceAll(passwordSigninSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const passwordSigninSchemaSQL = `ALTER TABLE @schema@.session_issuances DROP CONSTRAINT session_issuances_purpose_v2;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_v3 CHECK(purpose IN('identity.session.issue','identity.otp.signin','identity.password.signin'));
`
