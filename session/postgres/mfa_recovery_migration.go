package postgres

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFARecoveryMigrationSource adds closed recovery-code session schemas13/14
// (magic-link primary) and15/16 (password primary) after PasswordMFAMigrationSource
// in the same owned history. Allocate Version permanently and upgrade readers
// before selecting recovery sessions; old binaries reject the new profiles.
// Existing rows, historical migration SQL and issuance evidence are unchanged.
// Installing this source authenticates no code and creates no session authority.
type MFARecoveryMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one transactional forward constraint extension without IO.
// The existing runner owns locking and populated-state validation; malformed
// current state fails installation atomically. Cancellation remains observable.
func (s MFARecoveryMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	prior, err := (PasswordMFAMigrationSource{Schema: s.Schema, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	_, tail, ok := strings.Cut(prior[0].UpSQL(), "ADD CONSTRAINT session_record_binding_v7 CHECK(")
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
	// Retain the complete prior CHECK unchanged, including its fail-closed NULL
	// semantics. New profile branches cannot loosen a historical TOTP record.
	factor := strings.NewReplacer(
		"'Remember','VerifiedAt','ValidUntil']", "'Remember','VerifiedAt','ValidUntil','RecoverySetID','RecoverySetVersion']",
		"record->'MFA'->>'Method'='totp'", "record->'MFA'->>'Method'='recovery-code'",
	).Replace(mfaRecordSQL) + recoverySetRecordSQL
	magic := strings.NewReplacer("'7'", "'13'", "'8'", "'14'").Replace(magicLinkRecordSQL)
	password := strings.NewReplacer("'1' AND NOT record ? 'CSRF'", "'15' AND NOT record ? 'CSRF'", "'2' AND jsonb_typeof(record->'CSRF')", "'16' AND jsonb_typeof(record->'CSRF')").Replace(csrfSchemaSQL)
	_, password, ok = strings.Cut(password, "CHECK((\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	password, ok = strings.CutSuffix(password, ") IS TRUE);\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	passwordFactor := strings.NewReplacer("record->'MagicLink'->>'CommandID'", "record->'Authentication'->'Proof'->>'ID'", "record->'MagicLink'->>'AuthenticatedAt'", "record->'Authentication'->'Proof'->>'IssuedAt'", "record->'MagicLink'->>'ValidUntil'", "record->'Authentication'->'Proof'->>'ExpiresAt'").Replace(factor)
	sql := "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_record_binding_v7;\nALTER TABLE @schema@.sessions ADD CONSTRAINT session_record_binding_v8 CHECK((" + legacy + " OR (" + magic + " AND " + factor + ") OR ((" + password + " AND " + passwordMFAPrimarySQL + " AND " + passwordFactor + "))) IS TRUE);\n"
	sql += "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_credential_continuation_v4;\n" + strings.NewReplacer("session_credential_continuation_v1", "session_credential_continuation_v5", "IN ('1','2','3','4')", "IN ('1','2','3','4','7','8','9','10','11','12','13','14','15','16')").Replace(continuationSchemaSQL)
	m, err := migrations.NewMigration(s.Version, "identity_session_mfa_recovery", migrations.TransactionModeDefault, strings.ReplaceAll(sql, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const recoverySetRecordSQL = `
 AND jsonb_typeof(record->'MFA'->'RecoverySetID')='string'
 AND record->'MFA'->>'RecoverySetID' ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
 AND record->'MFA'->>'RecoverySetID'<>'AAAAAAAAAAAAAAAAAAAAAA'
 AND jsonb_typeof(record->'MFA'->'RecoverySetVersion')='number'
 AND (record->'MFA'->>'RecoverySetVersion')::numeric BETWEEN 1 AND 18446744073709551615
 AND trunc((record->'MFA'->>'RecoverySetVersion')::numeric)=(record->'MFA'->>'RecoverySetVersion')::numeric`
