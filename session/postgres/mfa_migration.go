package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFAMigrationSource adds complete magic-link/TOTP record schemas9/10 after
// MagicLinkMigrationSource in the same owned history. Allocate Version once.
// Upgrade all readers before selecting this profile; older binaries deny it.
// Legacy records, historical SQL and issuance evidence are not rewritten.
// This source does not authenticate factors or enable native session issuance.
type MFAMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only transactional constraint extension without IO.
// The existing runner owns locking, populated-state validation and atomic
// installation. Invalid configuration is redacted; cancellation is preserved.
func (s MFAMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_mfa_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	previous, err := (MagicLinkMigrationSource{Schema: s.Schema, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	// Preserve the exact predecessor expression; extend a separate closed branch
	// rather than reconstruct or silently relax existing record profiles.
	_, tail, ok := strings.Cut(previous[0].UpSQL(), "ADD CONSTRAINT session_record_binding_v5 CHECK(")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	legacy, _, ok := strings.Cut(tail, ");\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	mfaPrimary := strings.NewReplacer("'7'", "'9'", "'8'", "'10'").Replace(magicLinkRecordSQL)
	sql := "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_record_binding_v5;\nALTER TABLE @schema@.sessions ADD CONSTRAINT session_record_binding_v6 CHECK((((" + legacy + ") AND NOT record ? 'MFA') OR (" + mfaPrimary + " AND " + mfaRecordSQL + ")) IS TRUE);\n"
	for _, name := range []string{"EnrollmentVersion", "FactorAuthorityVersion", "ContinuationVersion"} {
		maximum := "18446744073709551615"
		if name == "ContinuationVersion" {
			maximum = "18446744073709551614"
		}
		sql += "ALTER TABLE @schema@.sessions ADD CONSTRAINT session_mfa_" + strings.ToLower(name) + " CHECK((NOT record ? 'MFA' OR (jsonb_typeof(record->'MFA'->'" + name + "')='number' AND (record->'MFA'->>'" + name + "')::numeric BETWEEN 1 AND " + maximum + " AND trunc((record->'MFA'->>'" + name + "')::numeric)=(record->'MFA'->>'" + name + "')::numeric)) IS TRUE);\n"
	}
	sql += "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_credential_continuation_v2;\n" + strings.NewReplacer("session_credential_continuation_v1", "session_credential_continuation_v3", "IN ('1','2','3','4')", "IN ('1','2','3','4','7','8','9','10')").Replace(continuationSchemaSQL)
	sql = strings.ReplaceAll(sql, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_mfa", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const mfaRecordSQL = `jsonb_typeof(record->'MFA')='object'
 AND record->'MFA' ?& ARRAY['CommandID','PrimaryCommandID','ContinuationID','ContinuationScopeDigest','Method','FactorID','EnrollmentVersion','FactorAuthorityVersion','ContinuationVersion','Remember','VerifiedAt','ValidUntil']
 AND (record->'MFA') - ARRAY['CommandID','PrimaryCommandID','ContinuationID','ContinuationScopeDigest','Method','FactorID','EnrollmentVersion','FactorAuthorityVersion','ContinuationVersion','Remember','VerifiedAt','ValidUntil']='{}'::jsonb
 AND jsonb_typeof(record->'MFA'->'CommandID')='string'
 AND jsonb_typeof(record->'MFA'->'PrimaryCommandID')='string'
 AND jsonb_typeof(record->'MFA'->'ContinuationID')='string'
 AND jsonb_typeof(record->'MFA'->'FactorID')='string'
 AND record->'MFA'->>'CommandID' ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
 AND record->'MFA'->>'PrimaryCommandID' ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
 AND record->'MFA'->>'ContinuationID' ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
 AND record->'MFA'->>'FactorID' ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
 AND record->'MFA'->>'CommandID'<>'AAAAAAAAAAAAAAAAAAAAAA'
 AND record->'MFA'->>'PrimaryCommandID'<>'AAAAAAAAAAAAAAAAAAAAAA'
 AND record->'MFA'->>'ContinuationID'<>'AAAAAAAAAAAAAAAAAAAAAA'
 AND record->'MFA'->>'FactorID'<>'AAAAAAAAAAAAAAAAAAAAAA'
 AND record->'MFA'->>'CommandID'<>record->'MFA'->>'PrimaryCommandID'
 AND record->'MFA'->>'CommandID'<>record->'MFA'->>'ContinuationID'
 AND record->'MFA'->>'PrimaryCommandID'<>record->'MFA'->>'ContinuationID'
 AND record->'MFA'->>'PrimaryCommandID'=record->'MagicLink'->>'CommandID'
 AND record->'MFA'->>'Method'='totp'
 AND jsonb_typeof(record->'MFA'->'ContinuationScopeDigest')='array'
 AND jsonb_array_length(record->'MFA'->'ContinuationScopeDigest')=32
 AND NOT (record->'MFA'->'ContinuationScopeDigest' @? '$[*] ? (@.type() != "number" || @ < 0 || @ > 255 || @.floor() != @)')
 AND record->'MFA'->'ContinuationScopeDigest'<>'[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]'::jsonb
 AND jsonb_typeof(record->'MFA'->'Remember')='object'
 AND record->'MFA'->'Remember' ?& ARRAY['Choice','AbsoluteTTL','IdleTTL','RefreshAfter','FreshFor']
 AND (record->'MFA'->'Remember') - ARRAY['Choice','AbsoluteTTL','IdleTTL','RefreshAfter','FreshFor']='{}'::jsonb
 AND record->'MFA'->'Remember'=record->'Remember'
 AND record->'Authority'->'Factor'->'Present'='true'::jsonb
 AND record->'Authority'->'Factor'->'Binding'->'Version'=record->'MFA'->'FactorAuthorityVersion'
 AND record->'Authority'->'Organization'->'Present'='false'::jsonb
 AND record->'Authority'->'Passkey'->'Present'='false'::jsonb
 AND jsonb_typeof(record->'MFA'->'VerifiedAt')='string'
 AND jsonb_typeof(record->'MFA'->'ValidUntil')='string'
 AND (record->'MagicLink'->>'AuthenticatedAt')::timestamptz<=(record->'MFA'->>'VerifiedAt')::timestamptz
 AND (record->'MFA'->>'VerifiedAt')::timestamptz<=(record->>'IssuedAt')::timestamptz
 AND (record->>'IssuedAt')::timestamptz<(record->'MFA'->>'ValidUntil')::timestamptz
 AND (record->'MFA'->>'ValidUntil')::timestamptz<=(record->'MagicLink'->>'ValidUntil')::timestamptz
 AND (record->'MFA'->>'ValidUntil')::timestamptz<=(record->'MFA'->>'VerifiedAt')::timestamptz+interval '5 minutes'`
