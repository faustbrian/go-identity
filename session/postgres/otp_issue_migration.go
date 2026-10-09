package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// OTPIssueMigrationSource extends the retained issuance table to consuming OTP
// signin. Allocate a permanent Version after IssueMigrationSource and the OTP
// record migration in the same history. Schema names the same owned namespace.
// Existing rows, keys and digests are unchanged; no second replay journal or
// destructive down migration is created. Install before enabling OTP effects.
type OTPIssueMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one bounded forward-only transactional constraint migration.
// The migration runner owns IO, table locking, populated-state validation and
// commitment; cancellation and malformed configuration fail before construction.
func (s OTPIssueMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_otp_issue_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_otp_issuance", migrations.TransactionModeDefault, strings.ReplaceAll(otpIssueSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const otpIssueSchemaSQL = `ALTER TABLE @schema@.session_issuances DROP CONSTRAINT session_issuances_purpose_check;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_v2 CHECK(purpose IN('identity.session.issue','identity.otp.signin'));
`
