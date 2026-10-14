package postgres

import (
	"context"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFAOTPRecordMigrationSource appends closed secondary OTP record schemas17/18
// for magic-link primary and19/20 for password primary after MFA recovery record
// history. Allocate Version permanently and upgrade readers before selection.
// Old TOTP/recovery checks and populated records remain unchanged. This selects
// storage only; actual native OTP/child/factor checks still own authentication.
type MFAOTPRecordMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only transactional constraint extension without IO.
// Existing runner locking, cancellation and fail-closed validation are retained.
func (s MFAOTPRecordMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	prior, err := (MFARecoveryMigrationSource{Schema: s.Schema, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	_, tail, ok := strings.Cut(prior[0].UpSQL(), "ADD CONSTRAINT session_record_binding_v8 CHECK(")
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
	factor := strings.ReplaceAll(mfaRecordSQL, "record->'MFA'->>'Method'='totp'", "record->'MFA'->>'Method'='otp'")
	magic := strings.NewReplacer("'7'", "'17'", "'8'", "'18'").Replace(magicLinkRecordSQL)
	password := strings.NewReplacer("'1' AND NOT record ? 'CSRF'", "'19' AND NOT record ? 'CSRF'", "'2' AND jsonb_typeof(record->'CSRF')", "'20' AND jsonb_typeof(record->'CSRF')").Replace(csrfSchemaSQL)
	_, password, ok = strings.Cut(password, "CHECK((\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	password, ok = strings.CutSuffix(password, ") IS TRUE);\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	passwordFactor := strings.NewReplacer("record->'MagicLink'->>'CommandID'", "record->'Authentication'->'Proof'->>'ID'", "record->'MagicLink'->>'AuthenticatedAt'", "record->'Authentication'->'Proof'->>'IssuedAt'", "record->'MagicLink'->>'ValidUntil'", "record->'Authentication'->'Proof'->>'ExpiresAt'").Replace(factor)
	sql := "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_record_binding_v8;\nALTER TABLE @schema@.sessions ADD CONSTRAINT session_record_binding_v9 CHECK((" + legacy + " OR (" + magic + " AND " + factor + ") OR ((" + password + " AND " + passwordMFAPrimarySQL + " AND " + passwordFactor + "))) IS TRUE);\n"
	sql += "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_credential_continuation_v5;\n" + strings.NewReplacer("session_credential_continuation_v1", "session_credential_continuation_v6", "IN ('1','2','3','4')", "IN ('1','2','3','4','7','8','9','10','11','12','13','14','15','16','17','18','19','20')").Replace(continuationSchemaSQL)
	m, err := migrations.NewMigration(s.Version, "identity_session_mfa_otp", migrations.TransactionModeDefault, strings.ReplaceAll(sql, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}
