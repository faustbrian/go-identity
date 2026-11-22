package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// SSOOIDCSigninMigrationSource admits enterprise OIDC callback issuance without
// rewriting existing history. Install both forward-only steps before enabling
// enterprise sign-in. When using social OAuth, install its purpose expansion
// first; neither migration requires enabling its corresponding sign-in feature.
type SSOOIDCSigninMigrationSource struct {
	Schema                     string
	Version, ValidationVersion migrations.Version
	PreviousConstraint         string
}

// Load builds a metadata-only expansion followed by separate validation. Each
// step bounds lock acquisition; the existing-row scan runs without the exclusive
// expansion lock. The caller's migration runner owns each transaction.
func (s SSOOIDCSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	knownPredecessor := passkeyIssuancePredecessor(s.PreviousConstraint) ||
		s.PreviousConstraint == "session_issuances_purpose_passkey_v1" ||
		s.PreviousConstraint == "session_issuances_purpose_passkey_signup_v1" ||
		s.PreviousConstraint == "session_issuances_purpose_oauth_v1"
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) || !knownPredecessor {
		return nil, identity.InvalidInputError{Field: "session_sso_oidc_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	schema := pgx.Identifier{s.Schema}.Sanitize()
	expansionSQL := strings.NewReplacer("@schema@", schema, "@schema_name@", s.Schema, "@previous@", s.PreviousConstraint).Replace(ssoOIDCSigninIssuanceExpansionSQL)
	expansion, err := migrations.NewMigration(s.Version, "identity_session_sso_oidc_expand", migrations.TransactionModeDefault, expansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validationSQL := `SET LOCAL lock_timeout = '5s';
ALTER TABLE ` + schema + `.session_issuances VALIDATE CONSTRAINT session_issuances_purpose_sso_oidc_v1;`
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_session_sso_oidc_validate", migrations.TransactionModeDefault, validationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expansion, validation}, nil
}

// Preserve the actual installed purpose expression so optional earlier issuance
// profiles retain their existing constraints; NOT VALID still checks new rows.
const ssoOIDCSigninIssuanceExpansionSQL = `SET LOCAL lock_timeout = '5s';
LOCK TABLE @schema@.session_issuances IN ACCESS EXCLUSIVE MODE;
DO $identity_sso_oidc_signin$
DECLARE previous_predicate text;
BEGIN
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.session_issuances'::pg_catalog.regclass
 AND c.conname='@previous@' AND c.contype='c' AND c.convalidated
 AND c.conkey=ARRAY[a.attnum];
 IF previous_predicate IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session enterprise OIDC predecessor constraint mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_issuances ADD CONSTRAINT session_issuances_purpose_sso_oidc_v1 CHECK ((%s) OR purpose=%L) NOT VALID','@schema_name@',previous_predicate,'identity.sso.oidc-callback');
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_issuances DROP CONSTRAINT %I','@schema_name@','@previous@');
END
$identity_sso_oidc_signin$;
`
