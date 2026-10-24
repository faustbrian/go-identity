package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PasskeySignupMigrationSource appends only the prospective-account issuance
// purpose to an explicitly selected existing CHECK. It preserves PostgreSQL's
// actual predecessor expression and populated rows, rather than assuming which
// optional methods are installed. Version follows installed session history.
// Install this suffix before enabling native signup. Existing migration bytes
// and issuance commitments remain unchanged; no schema/payload backfill occurs.
type PasskeySignupMigrationSource struct {
	Schema             string
	Version            migrations.Version
	PreviousConstraint string
}

// Load returns one forward-only migration without IO. The runner owns its
// transaction/timeouts. DDL locks session_issuances exclusively while validating
// the additive CHECK. Unknown, missing, unvalidated or wrong-column history fails at
// apply; no downgrade, exception swallowing or automatic history adoption occurs.
func (s PasskeySignupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) || (!passkeyIssuancePredecessor(s.PreviousConstraint) && s.PreviousConstraint != "session_issuances_purpose_passkey_v1") {
		return nil, identity.InvalidInputError{Field: "session_passkey_signup_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Reuse the owned additive-purpose DDL, with closed constant successor and
	// purpose substitutions. No request or arbitrary expression enters SQL.
	sql := strings.NewReplacer("session_issuances_purpose_passkey_v1", "session_issuances_purpose_passkey_signup_v1", "'identity.passkey.signin-verify'", "'identity.passkey.register-verify'").Replace(passkeyIssuanceSQL)
	sql = strings.NewReplacer("@schema@", pgx.Identifier{s.Schema}.Sanitize(), "@schema_name@", s.Schema, "@previous@", s.PreviousConstraint).Replace(sql)
	step, err := migrations.NewMigration(s.Version, "identity_session_passkey_signup", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{step}, nil
}
