package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

const ssoOIDCLogoutRevocationConstraint = "session_revocations_purpose_sso_oidc_v1"

// SSOOIDCLogoutMigrationSource expands the existing single-session revocation
// table for enterprise OIDC logout. Select the already installed purpose
// constraint: session_revocations_purpose_check or, if the issuer's RP logout
// suffix was installed, session_revocations_purpose_oidc_v1. The result supports
// both logout purposes without enabling either application capability. Do not
// additionally install the legacy issuer suffix after this shared expansion.
type SSOOIDCLogoutMigrationSource struct {
	Schema                     string
	Version, ValidationVersion migrations.Version
	PreviousConstraint         string
}

// Load returns a bounded metadata-only expansion followed by separate
// validation, with no downgrade. Apply both in separate runner transactions
// before enabling a writer that depends on this expansion.
func (s SSOOIDCLogoutMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	knownPredecessor := s.PreviousConstraint == "session_revocations_purpose_check" || s.PreviousConstraint == "session_revocations_purpose_oidc_v1"
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) || !knownPredecessor {
		return nil, identity.InvalidInputError{Field: "session_sso_oidc_logout_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	schema := pgx.Identifier{s.Schema}.Sanitize()
	expansionSQL := strings.NewReplacer("@schema@", schema, "@schema_name@", s.Schema, "@previous@", s.PreviousConstraint).Replace(ssoOIDCLogoutRevocationExpansionSQL)
	expansion, err := migrations.NewMigration(s.Version, "identity_session_sso_oidc_logout_expand", migrations.TransactionModeDefault, expansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_session_sso_oidc_logout_validate", migrations.TransactionModeDefault, `SET LOCAL lock_timeout = '5s';
ALTER TABLE `+schema+`.session_revocations VALIDATE CONSTRAINT `+ssoOIDCLogoutRevocationConstraint+`;`, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expansion, validation}, nil
}

// The predecessor predicate must still be valid at the schema transition. A
// brief exclusive lock protects the catalog read and atomic replacement; the
// later validation scans without this lock. Include the existing issuer purpose
// so consumers can select either owning protocol later without replaying DDL.
const ssoOIDCLogoutRevocationExpansionSQL = `SET LOCAL lock_timeout = '5s';
LOCK TABLE @schema@.session_revocations IN ACCESS EXCLUSIVE MODE;
DO $identity_sso_oidc_logout$
DECLARE previous_predicate text;
BEGIN
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.session_revocations'::pg_catalog.regclass
 AND c.conname='@previous@' AND c.contype='c' AND c.convalidated
 AND c.conkey=ARRAY[a.attnum];
 IF previous_predicate IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session enterprise logout predecessor constraint mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_revocations DROP CONSTRAINT %I, ADD CONSTRAINT ` + ssoOIDCLogoutRevocationConstraint + ` CHECK ((%s) OR purpose IN (%L,%L)) NOT VALID','@schema_name@','@previous@',previous_predicate,'identity.oauth-server.end-session','identity.sso.oidc-logout');
END
$identity_sso_oidc_logout$;
`
