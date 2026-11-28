package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// AdminRevokeMigrationSource adds the administrative single-session revocation
// purpose to the existing session_revocations owner without enabling a writer.
// PreviousConstraint may name its exact installed, validated purpose constraint:
// session_revocations_purpose_check, session_revocations_purpose_oidc_v1,
// session_revocations_purpose_sso_oidc_v1, or session_revocations_purpose_sso_saml_v1.
// An empty PreviousConstraint selects the sole installed constraint from that
// allowlist at execution time, rejecting missing, ambiguous, or malformed guards.
// Use that mode for stable application history when SSO is configured later;
// changing a previously allocated source's selector would change its checksum.
// The predicate and name are retained so later shared dynamic SSO expansions
// preserve this purpose. If selected, the legacy OIDCEndSessionMigrationSource
// must run before this expansion: its literal replacement would otherwise
// discard the administrative purpose. No other migration ordering is required
// beyond applying each source's prerequisites and separate validation phases.
type AdminRevokeMigrationSource struct {
	Schema                     string
	Version, ValidationVersion migrations.Version
	PreviousConstraint         string
}

// Load returns an append-only, forward-only expansion and separate validation
// without IO. Apply both in separate runner transactions before enabling an
// administrative revocation writer. Lock acquisition is bounded to five seconds
// in each transaction; the expansion takes only a metadata lock, while the later
// validation scans existing rows without that exclusive lock. Invalid scope,
// versions, predecessor names, nil contexts, and cancellation produce no work.
func (s AdminRevokeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	knownPredecessor := s.PreviousConstraint == "" ||
		s.PreviousConstraint == "session_revocations_purpose_check" ||
		s.PreviousConstraint == "session_revocations_purpose_oidc_v1" ||
		s.PreviousConstraint == ssoOIDCLogoutRevocationConstraint ||
		s.PreviousConstraint == ssoSAMLLogoutStartRevocationConstraint
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) || !knownPredecessor {
		return nil, identity.InvalidInputError{Field: "session_admin_revoke_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	schema := pgx.Identifier{s.Schema}.Sanitize()
	expansionTemplate := adminRevokeExpansionSQL
	validationTemplate := `SET LOCAL lock_timeout = '5s';
ALTER TABLE @schema@.session_revocations VALIDATE CONSTRAINT @previous@;`
	if s.PreviousConstraint == "" {
		expansionTemplate = adminRevokeSelectedExpansionSQL
		validationTemplate = adminRevokeSelectedValidationSQL
	}
	replacer := strings.NewReplacer("@schema@", schema, "@schema_name@", s.Schema, "@previous@", s.PreviousConstraint)
	expansionSQL := replacer.Replace(expansionTemplate)
	expansion, err := migrations.NewMigration(s.Version, "identity_session_admin_revoke_expand", migrations.TransactionModeDefault, expansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_session_admin_revoke_validate", migrations.TransactionModeDefault, replacer.Replace(validationTemplate), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expansion, validation}, nil
}

// As in the shared SSO expansions, the exclusive metadata lock keeps the
// validated predecessor stable between reading its predicate and replacing it.
// Retaining its name lets those existing expansions accept this predecessor
// without replacing their immutable SQL or losing the administrative purpose.
const adminRevokeExpansionSQL = `SET LOCAL lock_timeout = '5s';
LOCK TABLE @schema@.session_revocations IN ACCESS EXCLUSIVE MODE;
DO $identity_admin_revoke$
DECLARE previous_predicate text;
BEGIN
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.session_revocations'::pg_catalog.regclass
 AND c.conname='@previous@' AND c.contype='c' AND c.convalidated
 AND c.conkey=ARRAY[a.attnum];
 IF previous_predicate IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session administrative revocation predecessor constraint mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_revocations DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((%s) OR purpose=%L) NOT VALID','@schema_name@','@previous@','@previous@',previous_predicate,'identity.admin.session-revoke');
END
$identity_admin_revoke$;
`

// Count all known names before checking the chosen guard's shape. Otherwise an
// invalid or unvalidated second known guard could be hidden by the shape filter.
const adminRevokeSelectPredecessorSQL = `
 SELECT count(*), min(c.conname::text) INTO predecessor_count, previous_constraint
 FROM pg_catalog.pg_constraint c
 WHERE c.conrelid='@schema@.session_revocations'::pg_catalog.regclass
 AND c.conname IN ('session_revocations_purpose_check','session_revocations_purpose_oidc_v1','session_revocations_purpose_sso_oidc_v1','session_revocations_purpose_sso_saml_v1');
 IF predecessor_count<>1 THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session administrative revocation predecessor constraint missing or ambiguous';
 END IF;
`

const adminRevokeSelectedExpansionSQL = `SET LOCAL lock_timeout = '5s';
LOCK TABLE @schema@.session_revocations IN ACCESS EXCLUSIVE MODE;
DO $identity_admin_revoke$
DECLARE
 predecessor_count bigint;
 previous_constraint text;
 previous_predicate text;
BEGIN` + adminRevokeSelectPredecessorSQL + `
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.session_revocations'::pg_catalog.regclass
 AND c.conname=previous_constraint AND c.contype='c' AND c.convalidated
 AND c.conkey=ARRAY[a.attnum];
 IF previous_predicate IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session administrative revocation predecessor constraint mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_revocations DROP CONSTRAINT %I, ADD CONSTRAINT %I CHECK ((%s) OR purpose=%L) NOT VALID','@schema_name@',previous_constraint,previous_constraint,previous_predicate,'identity.admin.session-revoke');
END
$identity_admin_revoke$;
`

// SHARE UPDATE EXCLUSIVE prevents a concurrent constraint replacement between
// selection and validation without blocking normal writes during the scan. The
// exact quoted literal avoids mistaking a longer purpose for this expansion.
const adminRevokeSelectedValidationSQL = `SET LOCAL lock_timeout = '5s';
LOCK TABLE @schema@.session_revocations IN SHARE UPDATE EXCLUSIVE MODE;
DO $identity_admin_revoke_validate$
DECLARE
 predecessor_count bigint;
 previous_constraint text;
 previous_predicate text;
BEGIN` + adminRevokeSelectPredecessorSQL + `
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='purpose' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.session_revocations'::pg_catalog.regclass
 AND c.conname=previous_constraint AND c.contype='c'
 AND c.conkey=ARRAY[a.attnum];
 IF previous_predicate IS NULL OR pg_catalog.strpos(previous_predicate,pg_catalog.quote_literal('identity.admin.session-revoke'))=0 THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session administrative revocation validation constraint mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.session_revocations VALIDATE CONSTRAINT %I','@schema_name@',previous_constraint);
END
$identity_admin_revoke_validate$;
`
