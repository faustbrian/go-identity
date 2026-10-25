package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PasskeyMFAMigrationSource adds completed passkey/TOTP schemas11/12 to an
// explicitly selected installed MFA record constraint. Existing password MFA
// records keep their closed method/purpose branch; no row or old migration is
// rewritten. PreviousConstraint must describe the installed v6-v9 record
// history, including its original MFA numeric constraints. Allocate Version
// permanently after all installed steps. Upgrade readers before enabling the
// profile. The existing runner owns the transaction; ALTER locks sessions and
// validates populated rows. This history grants no authentication or issuance.
type PasskeyMFAMigrationSource struct {
	Schema             string
	Version            migrations.Version
	PreviousConstraint string
}

// Load returns one bounded forward-only migration without IO. Unknown, missing
// or unvalidated predecessor history fails, without downgrading old checks or
// adopting arbitrary expressions. Cancellation retains the original error.
func (s PasskeyMFAMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	validPrior := s.PreviousConstraint == "session_record_binding_v6" || s.PreviousConstraint == "session_record_binding_v7" || s.PreviousConstraint == "session_record_binding_v8" || s.PreviousConstraint == "session_record_binding_v9"
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) || !validPrior {
		return nil, identity.InvalidInputError{Field: "session_passkey_mfa_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	previousContinuation := map[string]string{
		"session_record_binding_v6": "session_credential_continuation_v3",
		"session_record_binding_v7": "session_credential_continuation_v4",
		"session_record_binding_v8": "session_credential_continuation_v5",
		"session_record_binding_v9": "session_credential_continuation_v6",
	}[s.PreviousConstraint]
	base := strings.NewReplacer("'1' AND NOT record ? 'CSRF'", "'11' AND NOT record ? 'CSRF'", "'2' AND jsonb_typeof(record->'CSRF')", "'12' AND jsonb_typeof(record->'CSRF')").Replace(csrfSchemaSQL)
	_, base, ok := strings.Cut(base, "CHECK((\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	base, ok = strings.CutSuffix(base, ") IS TRUE);\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	// These closed substitutions select the pinned authentication proof profile
	// (AssurancePhishingResistant=3), not a client-selected method or SQL fragment.
	primary := strings.NewReplacer("'Method'='password'", "'Method'='passkey'", "'Assurance'='1'", "'Assurance'='3'", string(session.PasswordMFAPrimaryPurpose), string(session.PasskeyMFAPrimaryPurpose)).Replace(passwordMFAPrimarySQL)
	factor := strings.NewReplacer(
		"record->'MagicLink'->>'CommandID'", "record->'Authentication'->'Proof'->>'ID'",
		"record->'MagicLink'->>'AuthenticatedAt'", "record->'Authentication'->'Proof'->>'IssuedAt'",
		"record->'MagicLink'->>'ValidUntil'", "record->'Authentication'->'Proof'->>'ExpiresAt'",
		"record->'Authority'->'Passkey'->'Present'='false'::jsonb", "record->'Authority'->'Passkey'->'Present'='true'::jsonb",
	).Replace(mfaRecordSQL)
	branch := base + " AND " + primary + " AND " + factor + passkeyMFAOwnerBindingSQL
	sql := strings.NewReplacer("@schema@", pgx.Identifier{s.Schema}.Sanitize(), "@schema_name@", s.Schema, "@previous@", s.PreviousConstraint, "@previous_continuation@", previousContinuation, "@branch@", strings.ReplaceAll(branch, "'", "''")).Replace(passkeyMFARecordUpgradeSQL)
	step, err := migrations.NewMigration(s.Version, "identity_session_passkey_mfa", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{step}, nil
}

const passkeyMFAOwnerBindingSQL = `
 AND jsonb_typeof(record->'Authority'->'Passkey'->'Binding'->'ScopeKey')='string'
 AND length(record->'Authority'->'Passkey'->'Binding'->>'ScopeKey') BETWEEN 1 AND 256
 AND jsonb_typeof(record->'Authority'->'Passkey'->'Binding'->'Version')='number'
 AND (record->'Authority'->'Passkey'->'Binding'->>'Version')::numeric BETWEEN 1 AND 18446744073709551615
 AND trunc((record->'Authority'->'Passkey'->'Binding'->>'Version')::numeric)=(record->'Authority'->'Passkey'->'Binding'->>'Version')::numeric`

// Only bounded schema/history names and the owned constant branch enter DDL.
// Preserve the actual validated predecessor expression, including its NULL
// semantics, rather than guessing which optional authentication rows exist.
const passkeyMFARecordUpgradeSQL = `LOCK TABLE @schema@.sessions IN ACCESS EXCLUSIVE MODE;
DO $identity_passkey_mfa$
DECLARE previous_predicate text; previous_continuation text;
BEGIN
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_predicate
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='record' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.sessions'::pg_catalog.regclass
 AND c.conname='@previous@' AND c.contype='c' AND c.convalidated
 AND a.attnum=ANY(c.conkey);
 IF previous_predicate IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session passkey MFA predecessor mismatch';
 END IF;
 SELECT pg_catalog.pg_get_expr(c.conbin,c.conrelid) INTO previous_continuation
 FROM pg_catalog.pg_constraint c
 JOIN pg_catalog.pg_attribute a ON a.attrelid=c.conrelid AND a.attname='record' AND NOT a.attisdropped
 WHERE c.conrelid='@schema@.sessions'::pg_catalog.regclass
 AND c.conname='@previous_continuation@' AND c.contype='c' AND c.convalidated
 AND a.attnum=ANY(c.conkey);
 IF previous_continuation IS NULL THEN
  RAISE EXCEPTION USING ERRCODE='55000', MESSAGE='session passkey MFA continuation predecessor mismatch';
 END IF;
 EXECUTE pg_catalog.format('ALTER TABLE %I.sessions DROP CONSTRAINT %I','@schema_name@','@previous@');
 EXECUTE pg_catalog.format('ALTER TABLE %I.sessions ADD CONSTRAINT session_record_binding_passkey_mfa_v1 CHECK (((%s) OR (@branch@)) IS TRUE)','@schema_name@',previous_predicate);
 EXECUTE pg_catalog.format('ALTER TABLE %I.sessions DROP CONSTRAINT %I','@schema_name@','@previous_continuation@');
 EXECUTE pg_catalog.format('ALTER TABLE %I.sessions ADD CONSTRAINT session_credential_continuation_passkey_mfa_v1 CHECK (((%s) OR (record->>''Schema'' IN (''11'',''12'') AND NOT record ? ''Continuation'' AND record->''Authentication''->''Proof''->>''Method''=''passkey'')) IS TRUE)','@schema_name@',previous_continuation);
END
$identity_passkey_mfa$;
`
