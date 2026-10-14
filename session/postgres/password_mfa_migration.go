package postgres

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PasswordMFAMigrationSource adds closed password/TOTP schemas11/12 after
// MFAMigrationSource in the same owned history. Upgrade readers before selecting
// these records. Existing SQL, rows and original issuance evidence are retained;
// this migration neither authenticates a password nor completes a factor.
type PasswordMFAMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns a forward-only transactional constraint extension without IO.
// The existing runner owns locking, populated-state validation and commitment.
func (s PasswordMFAMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	prior, err := (MFAMigrationSource{Schema: s.Schema, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	_, tail, ok := strings.Cut(prior[0].UpSQL(), "ADD CONSTRAINT session_record_binding_v6 CHECK(")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	legacy, _, ok := strings.Cut(tail, ";\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	legacy, ok = strings.CutSuffix(legacy, ")")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	// The complete old CHECK expression remains one branch, including IS TRUE.
	passwordBase := strings.NewReplacer("'1' AND NOT record ? 'CSRF'", "'11' AND NOT record ? 'CSRF'", "'2' AND jsonb_typeof(record->'CSRF')", "'12' AND jsonb_typeof(record->'CSRF')").Replace(csrfSchemaSQL)
	_, passwordBase, ok = strings.Cut(passwordBase, "CHECK((\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	passwordBase, ok = strings.CutSuffix(passwordBase, ") IS TRUE);\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	factor := strings.NewReplacer("record->'MagicLink'->>'CommandID'", "record->'Authentication'->'Proof'->>'ID'", "record->'MagicLink'->>'AuthenticatedAt'", "record->'Authentication'->'Proof'->>'IssuedAt'", "record->'MagicLink'->>'ValidUntil'", "record->'Authentication'->'Proof'->>'ExpiresAt'").Replace(mfaRecordSQL)
	sql := "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_record_binding_v6;\nALTER TABLE @schema@.sessions ADD CONSTRAINT session_record_binding_v7 CHECK((" + legacy + " OR ((" + passwordBase + " AND " + passwordMFAPrimarySQL + " AND " + factor + "))) IS TRUE);\n"
	sql += "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_credential_continuation_v3;\n" + strings.NewReplacer("session_credential_continuation_v1", "session_credential_continuation_v4", "IN ('1','2','3','4')", "IN ('1','2','3','4','7','8','9','10','11','12')").Replace(continuationSchemaSQL)
	m, err := migrations.NewMigration(s.Version, "identity_session_password_mfa", migrations.TransactionModeDefault, strings.ReplaceAll(sql, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const passwordMFAPrimarySQL = `NOT record ? 'MagicLink' AND NOT record ? 'OTP' AND NOT record ? 'Continuation'
 AND record->'Authentication'->>'Kind'='1'
 AND record->'Authentication'->'Proof'->>'Method'='password'
 AND record->'Authentication'->'Proof'->>'Assurance'='1'
 AND record->'Authentication'->'Proof'->>'Purpose'='identity.password.mfa-primary'
 AND record->'Authentication'->'Proof'->>'Tenant'=tenant_id
 AND record->'Authentication'->'Proof'->>'Subject'=user_id
 AND record->'Authentication'->'Proof'->>'Audience'=record->>'Audience'
 AND jsonb_typeof(record->'Authentication'->'CredentialID')='string'
 AND length(record->'Authentication'->>'CredentialID') BETWEEN 1 AND 128
 AND jsonb_typeof(record->'Authentication'->'CredentialVersion')='number'
 AND (record->'Authentication'->>'CredentialVersion')::numeric BETWEEN 1 AND 18446744073709551615
 AND trunc((record->'Authentication'->>'CredentialVersion')::numeric)=(record->'Authentication'->>'CredentialVersion')::numeric
 AND jsonb_typeof(record->'Authentication'->'ProofVersion')='number'
 AND (record->'Authentication'->>'ProofVersion')::numeric BETWEEN 1 AND 18446744073709551615
 AND trunc((record->'Authentication'->>'ProofVersion')::numeric)=(record->'Authentication'->>'ProofVersion')::numeric`
