package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// OAuthSigninMigrationSource adds only the existing-account callback issuance
// purpose to an explicitly selected installed purpose CHECK. Version expands
// the predicate without scanning existing rows; ValidationVersion follows in a
// separate transaction whose validation lock permits ordinary reads/writes.
// Both permanent versions must follow installed history. Original migration
// bytes, populated records and issuance commitments are unchanged.
//
// Install both steps before enabling native signin, and retire readers unable
// to admit provider sessions before issuance. Rollback disables that profile;
// forward history and retained evidence are not removed. No backfill, automatic
// migration, transaction owner or destructive downgrade is introduced.
type OAuthSigninMigrationSource struct {
	Schema                     string
	Version, ValidationVersion migrations.Version
	PreviousConstraint         string
}

// Load creates two bounded forward-only steps without IO. The migration runner
// owns transaction, cancellation and namespace serialization. Expansion holds
// an exclusive metadata lock, with a five-second lock timeout and no validation
// scan; the separate validation step uses the same lock-acquisition bound.
// Missing, unknown, unvalidated or non-purpose predecessors fail at application,
// rather than adopting drift. Zero/invalid configuration returns redacted error.
func (s OAuthSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	knownPredecessor := passkeyIssuancePredecessor(s.PreviousConstraint) || s.PreviousConstraint == "session_issuances_purpose_passkey_v1" || s.PreviousConstraint == "session_issuances_purpose_passkey_signup_v1"
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) || !knownPredecessor {
		return nil, identity.InvalidInputError{Field: "session_oauth_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	schema := pgx.Identifier{s.Schema}.Sanitize()
	expansionSQL := strings.NewReplacer("@schema@", schema, "@schema_name@", s.Schema, "@previous@", s.PreviousConstraint).Replace(oauthSigninIssuanceExpansionSQL)
	expansion, err := migrations.NewMigration(s.Version, "identity_session_oauth_signin_expand", migrations.TransactionModeDefault, expansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validationSQL := `SET LOCAL lock_timeout = '5s';
ALTER TABLE ` + schema + `.session_issuances VALIDATE CONSTRAINT session_issuances_purpose_oauth_v1;`
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_session_oauth_signin_validate", migrations.TransactionModeDefault, validationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expansion, validation}, nil
}

// The catalog expression is the already validated installed predicate, not a
// guessed list of optional login methods. NOT VALID still checks every new row;
// its only deferred work is the existing-row scan, in the later validation step.
const oauthSigninIssuanceExpansionSQL = `SET LOCAL lock_timeout = '5s';
LOCK TABLE @schema@.session_issuances IN ACCESS EXCLUSIVE MODE;
DO $identity_oauth_signin$
DECLARE previous_predicate text;
BEGIN
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.session_issuances'::pg_catalog.regclass
 AND c.conname='@previous@' AND c.contype='c' AND c.convalidated
 AND c.conkey=ARRAY[a.attnum];
 IF previous_predicate IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session OAuth predecessor constraint mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_issuances ADD CONSTRAINT session_issuances_purpose_oauth_v1 CHECK ((%s) OR purpose=%L) NOT VALID','@schema_name@',previous_predicate,'identity.oauth.callback');
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_issuances DROP CONSTRAINT %I','@schema_name@','@previous@');
END
$identity_oauth_signin$;
`
