package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PasskeySigninMigrationSource appends one purpose to an explicitly selected
// already installed session-issuance constraint. PreviousConstraint must name
// that actual supported history; no login method, anonymous or device tables
// become dependencies. Allocate a permanent Version after every installed step.
// The existing validated purpose predicate is preserved from PostgreSQL's own
// expression tree, not reconstructed from optional feature guesses. Existing
// rows, original migration SQL/checksums and issuance commitments are unchanged.
// Install this suffix last and retire binaries that cannot read passkey sessions
// before enabling issuance. The existing runner owns the transaction/timeouts;
// ALTER takes an exclusive table lock and validates the additive CHECK.
type PasskeySigninMigrationSource struct {
	Schema             string
	Version            migrations.Version
	PreviousConstraint string
}

// Load returns one forward-only transactional migration without IO. Unknown,
// unvalidated, missing or non-purpose predecessor checks fail visibly at apply;
// there is no downgrade, exception swallowing or schema-drift adoption.
func (s PasskeySigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) || !passkeyIssuancePredecessor(s.PreviousConstraint) {
		return nil, identity.InvalidInputError{Field: "session_passkey_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.NewReplacer("@schema@", pgx.Identifier{s.Schema}.Sanitize(), "@schema_name@", s.Schema, "@previous@", s.PreviousConstraint).Replace(passkeyIssuanceSQL)
	step, err := migrations.NewMigration(s.Version, "identity_session_passkey_signin", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{step}, nil
}

func passkeyIssuancePredecessor(s string) bool {
	switch s {
	case "session_issuances_purpose_check", "session_issuances_purpose_v2", "session_issuances_purpose_v3", "session_issuances_purpose_v4", "session_issuances_purpose_v5", "session_issuances_purpose_v6", "session_issuances_purpose_v7", "session_issuances_purpose_v8", "session_issuances_purpose_username_v1", "session_issuances_purpose_phone_password_v1", "session_issuances_purpose_phone_otp_v1", "session_issuances_purpose_anonymous_v1", "session_issuances_purpose_anonymous_upgrade_v1":
		return true
	default:
		return false
	}
}

// Only catalog-produced expression SQL is interpolated. Schema and predecessor
// are separately bounded trusted configuration, and dynamic identifiers/values
// use PostgreSQL format quoting. This is a one-time additive DDL operation, not
// a runtime authorization function or a second workflow/protocol owner.
const passkeyIssuanceSQL = `LOCK TABLE @schema@.session_issuances IN ACCESS EXCLUSIVE MODE;
DO $identity_passkey$
DECLARE previous_predicate text;
BEGIN
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.session_issuances'::pg_catalog.regclass
 AND c.conname='@previous@' AND c.contype='c' AND c.convalidated
 AND c.conkey=ARRAY[a.attnum];
 IF previous_predicate IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session passkey predecessor constraint mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_issuances DROP CONSTRAINT %I','@schema_name@','@previous@');
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_issuances ADD CONSTRAINT session_issuances_purpose_passkey_v1 CHECK ((%s) OR purpose=%L)','@schema_name@',previous_predicate,'identity.passkey.signin-verify');
END
$identity_passkey$;
`
