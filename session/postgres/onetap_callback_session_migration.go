package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// OneTapCallbackSessionMigrationSource adds only One Tap callback issuance to
// an explicitly selected, validated session-purpose CHECK. Install both steps
// before selecting the One Tap session writer, using permanent versions after
// installed history. The expansion preserves the complete installed predicate
// and rows; ValidationVersion performs its existing-row scan separately.
// This opt-in source does not enable a flow or apply migrations. On code
// rollback, disable the writer and retain this forward-only issuance history.
type OneTapCallbackSessionMigrationSource struct {
	Schema                     string
	Version, ValidationVersion migrations.Version
	PreviousConstraint         string
}

var _ migrations.Source = OneTapCallbackSessionMigrationSource{}

// Load returns two transactional steps without IO. The runner owns transaction,
// cancellation and namespace serialization. Each step bounds lock acquisition
// to five seconds; expansion takes an exclusive metadata lock without scanning
// retained rows, while separate validation permits ordinary reads and writes.
// Missing, unvalidated or non-purpose predecessors fail at application rather
// than adopting drift. Invalid configuration returns no partial history.
func (s OneTapCallbackSessionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) || !oneTapCallbackSessionPredecessor(s.PreviousConstraint) {
		return nil, identity.InvalidInputError{Field: "session_onetap_callback_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	schema := pgx.Identifier{s.Schema}.Sanitize()
	expansionSQL := strings.NewReplacer("@schema@", schema, "@schema_name@", s.Schema, "@previous@", s.PreviousConstraint).Replace(oneTapCallbackSessionExpansionSQL)
	expansion, err := migrations.NewMigration(s.Version, "identity_session_onetap_callback_expand", migrations.TransactionModeDefault, expansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validationSQL := `SET LOCAL lock_timeout = '5s';
ALTER TABLE ` + schema + `.session_issuances VALIDATE CONSTRAINT session_issuances_purpose_onetap_v1;`
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_session_onetap_callback_validate", migrations.TransactionModeDefault, validationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expansion, validation}, nil
}

func oneTapCallbackSessionPredecessor(name string) bool {
	if passkeyIssuancePredecessor(name) {
		return true
	}
	switch name {
	case "session_issuances_purpose_passkey_v1", "session_issuances_purpose_passkey_signup_v1",
		"session_issuances_purpose_oauth_v1", "session_issuances_purpose_sso_oidc_v1",
		"session_issuances_purpose_sso_oauth2_v1", "session_issuances_purpose_sso_saml_v1",
		"session_issuances_purpose_sso_saml_idp_v1":
		return true
	default:
		return false
	}
}

// PostgreSQL's validated expression retains optional predecessor profiles; a
// guessed purpose list could discard an installed method. The exact named CHECK
// must cover purpose alone on this table. NOT VALID still enforces every new row.
const oneTapCallbackSessionExpansionSQL = `SET LOCAL lock_timeout = '5s';
LOCK TABLE @schema@.session_issuances IN ACCESS EXCLUSIVE MODE;
DO $identity_onetap_callback_session$
DECLARE previous_predicate text;
BEGIN
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.session_issuances'::pg_catalog.regclass
 AND c.conname='@previous@' AND c.contype='c' AND c.convalidated
 AND c.conkey=ARRAY[a.attnum];
 IF previous_predicate IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session One Tap predecessor constraint mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_issuances ADD CONSTRAINT session_issuances_purpose_onetap_v1 CHECK ((%s) OR purpose=%L) NOT VALID','@schema_name@',previous_predicate,'identity.oauth.onetap-callback');
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_issuances DROP CONSTRAINT %I','@schema_name@','@previous@');
END
$identity_onetap_callback_session$;
`
