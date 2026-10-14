package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MagicLinkMigrationSource admits complete original magic-link provenance in
// schemas7/8 after CredentialContinuationMigrationSource in the same permanent
// migration history. Upgrade all readers/writers before selecting these records:
// older binaries reject them. Existing payloads, constraints' legacy semantics
// and historical checksums remain unchanged. It neither authenticates nor
// enables session issuance. Zero configuration is invalid; Load performs no IO.
type MagicLinkMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one transactional forward-only migration. Populated malformed
// records abort the whole upgrade; the existing runner owns locks and commit.
// Configuration errors are redacted and caller cancellation is preserved.
func (s MagicLinkMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_magic_link_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Reuse the preceding owned constraint expression byte-for-byte instead
	// of rewriting applied history or maintaining a second legacy definition.
	legacy := strings.NewReplacer("IN ('1','2')", "IN ('1','2','5','6')", "IN ('1','3')", "IN ('1','3','5')", "IN ('2','4')", "IN ('2','4','6')").Replace(otpSchemaSQL)
	_, legacy, ok := strings.Cut(legacy, "CHECK((\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	legacy, ok = strings.CutSuffix(legacy, ") IS TRUE);\n")
	if !ok {
		return nil, identity.UnavailableError{}
	}
	// The cut retains the opening parenthesis represented by CHECK(( and
	// excludes its final check wrapper; the original expression stays grouped.
	sql := "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_record_binding_v4;\nALTER TABLE @schema@.sessions ADD CONSTRAINT session_record_binding_v5 CHECK(((\n" + legacy + " AND NOT record ? 'MagicLink') OR (" + magicLinkRecordSQL + ")) IS TRUE);\n"
	sql += "ALTER TABLE @schema@.sessions DROP CONSTRAINT session_credential_continuation_v1;\n" + strings.NewReplacer("session_credential_continuation_v1", "session_credential_continuation_v2", "IN ('1','2','3','4')", "IN ('1','2','3','4','7','8')").Replace(continuationSchemaSQL)
	m, err := migrations.NewMigration(s.Version, "identity_session_magic_link", migrations.TransactionModeDefault, strings.ReplaceAll(sql, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const magicLinkRecordSQL = `record->>'TenantID'=tenant_id AND record->>'SessionID'=session_id
 AND record->>'UserID'=user_id AND record->>'FamilyID'=family_id
 AND (record->>'Version')::numeric=version AND (record->>'FamilyVersion')::numeric=family_version
 AND record->>'Schema' IN ('7','8') AND record->'Authentication'->>'Kind'='4'
 AND NOT record ? 'OTP' AND NOT record ? 'Continuation'
 AND jsonb_typeof(record->'MagicLink')='object'
 AND record->'MagicLink' ?& ARRAY['CommandID','RequestCommandID','CapabilityID','IdentifierID','IdentifierVersion','VerificationVersion','AuthenticatedAt','ValidUntil']
 AND (record->'MagicLink') - ARRAY['CommandID','RequestCommandID','CapabilityID','IdentifierID','IdentifierVersion','VerificationVersion','AuthenticatedAt','ValidUntil']='{}'::jsonb
 AND jsonb_typeof(record->'MagicLink'->'CommandID')='string'
 AND jsonb_typeof(record->'MagicLink'->'RequestCommandID')='string'
 AND jsonb_typeof(record->'MagicLink'->'CapabilityID')='string'
 AND jsonb_typeof(record->'MagicLink'->'IdentifierID')='string'
 AND jsonb_typeof(record->'MagicLink'->'AuthenticatedAt')='string'
 AND jsonb_typeof(record->'MagicLink'->'ValidUntil')='string'
 AND jsonb_typeof(record->'MagicLink'->'IdentifierVersion')='number'
 AND (record->'MagicLink'->>'IdentifierVersion')::numeric BETWEEN 1 AND 18446744073709551615
 AND trunc((record->'MagicLink'->>'IdentifierVersion')::numeric)=(record->'MagicLink'->>'IdentifierVersion')::numeric
 AND jsonb_typeof(record->'MagicLink'->'VerificationVersion')='number'
 AND (record->'MagicLink'->>'VerificationVersion')::numeric BETWEEN 1 AND 18446744073709551615
 AND trunc((record->'MagicLink'->>'VerificationVersion')::numeric)=(record->'MagicLink'->>'VerificationVersion')::numeric
 AND ((record->>'Schema'='7' AND NOT record ? 'CSRF') OR
 (record->>'Schema'='8' AND jsonb_typeof(record->'CSRF')='object'
 AND jsonb_typeof(record->'CSRF'->'Binding')='object'
 AND record->'CSRF'->'Binding'->>'TenantID'=tenant_id AND record->'CSRF'->'Binding'->>'SessionID'=session_id
 AND (record->'CSRF'->'Binding'->>'SessionVersion')::numeric=version
 AND jsonb_typeof(record->'CSRF'->'KeyVersion')='number'
 AND (record->'CSRF'->>'KeyVersion')::numeric BETWEEN 1 AND 4294967295
 AND trunc((record->'CSRF'->>'KeyVersion')::numeric)=(record->'CSRF'->>'KeyVersion')::numeric
 AND jsonb_typeof(record->'CSRF'->'Digest')='array' AND jsonb_array_length(record->'CSRF'->'Digest')=32))`
