package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

const ssoSAMLLogoutStartRevocationConstraint = "session_revocations_purpose_sso_saml_v1"

// SSOSAMLLogoutStartMigrationSource adds SAML logout-start journals without
// enabling a writer. PreviousConstraint names the exact currently installed
// base, RP logout, or enterprise OIDC constraint. The new constraint also
// accepts both previously supported OIDC purposes; do not subsequently apply
// either older expansion on top of this one.
type SSOSAMLLogoutStartMigrationSource struct {
	Schema                     string
	Version, ValidationVersion migrations.Version
	PreviousConstraint         string
}

// Load returns separate bounded expansion and validation migrations. The
// expansion preserves the old validated predicate and uses a brief metadata
// lock; the later scan permits normal writes. Both precede writer activation.
func (s SSOSAMLLogoutStartMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	knownPredecessor := s.PreviousConstraint == "session_revocations_purpose_check" ||
		s.PreviousConstraint == "session_revocations_purpose_oidc_v1" || s.PreviousConstraint == ssoOIDCLogoutRevocationConstraint
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) || !knownPredecessor {
		return nil, identity.InvalidInputError{Field: "session_sso_saml_logout_start_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	schema := pgx.Identifier{s.Schema}.Sanitize()
	expansionSQL := strings.NewReplacer("@schema@", schema, "@schema_name@", s.Schema, "@previous@", s.PreviousConstraint).Replace(ssoSAMLLogoutStartExpansionSQL)
	expansion, err := migrations.NewMigration(s.Version, "identity_session_sso_saml_logout_start_expand", migrations.TransactionModeDefault, expansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_session_sso_saml_logout_start_validate", migrations.TransactionModeDefault, `SET LOCAL lock_timeout = '5s';
ALTER TABLE `+schema+`.session_revocations VALIDATE CONSTRAINT `+ssoSAMLLogoutStartRevocationConstraint+`;`, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expansion, validation}, nil
}

const ssoSAMLLogoutStartExpansionSQL = `SET LOCAL lock_timeout = '5s';
LOCK TABLE @schema@.session_revocations IN ACCESS EXCLUSIVE MODE;
DO $identity_sso_saml_logout$
DECLARE previous_predicate text;
BEGIN
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.session_revocations'::pg_catalog.regclass
 AND c.conname='@previous@' AND c.contype='c' AND c.convalidated
 AND c.conkey=ARRAY[a.attnum];
 IF previous_predicate IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session SAML logout predecessor constraint mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_revocations DROP CONSTRAINT %I, ADD CONSTRAINT ` + ssoSAMLLogoutStartRevocationConstraint + ` CHECK ((%s) OR purpose IN (%L,%L,%L)) NOT VALID','@schema_name@','@previous@',previous_predicate,'identity.oauth-server.end-session','identity.sso.oidc-logout','identity.sso.saml-logout-start');
END
$identity_sso_saml_logout$;
`
