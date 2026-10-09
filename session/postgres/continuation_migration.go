package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// CredentialContinuationMigrationSource admits continued password records in
// schemas 5/6. Allocate a permanent Version after OTPMigrationSource in the same
// owned Schema and sole migration history. Upgrade all relevant readers/writers
// before selecting continuation: old binaries reject these records. Existing
// rows and historical SQL/checksums are unchanged. This migration grants no
// authentication or password-change authority. Zero configuration is invalid.
type CredentialContinuationMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one transactional forward migration without IO. The migration
// runner owns locking and commitment; malformed populated rows abort the entire
// upgrade. Context cancellation is preserved; configuration errors are redacted.
func (s CredentialContinuationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_continuation_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Preserve the predecessor's complete OTP/CSRF and cross-column checks.
	// Extend its admitted schema pairs, then constrain continuation separately;
	// do not weaken legacy profiles or rewrite their applied migration source.
	sql := strings.NewReplacer(
		"DROP CONSTRAINT session_record_binding_v2", "DROP CONSTRAINT session_record_binding_v3",
		"ADD CONSTRAINT session_record_binding_v3", "ADD CONSTRAINT session_record_binding_v4",
		"IN ('1','2')", "IN ('1','2','5','6')",
		"IN ('1','3')", "IN ('1','3','5')",
		"IN ('2','4')", "IN ('2','4','6')",
	).Replace(otpSchemaSQL) + continuationSchemaSQL
	m, err := migrations.NewMigration(s.Version, "identity_session_credential_continuation", migrations.TransactionModeDefault, strings.ReplaceAll(sql, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const continuationSchemaSQL = `ALTER TABLE @schema@.sessions ADD CONSTRAINT session_credential_continuation_v1 CHECK((
 (record->>'Schema' IN ('1','2','3','4') AND NOT record ? 'Continuation')
 OR (record->>'Schema' IN ('5','6') AND NOT record ? 'OTP'
 AND record->'Authentication'->>'Kind'='1'
 AND record->'Authentication'->'Proof'->>'Method'='password'
 AND jsonb_typeof(record->'Continuation')='object'
 AND record->'Continuation' ?& ARRAY['CommandID','BeforeAuthorityVersion','BeforeCredentialVersion']
 AND (record->'Continuation') - ARRAY['CommandID','BeforeAuthorityVersion','BeforeCredentialVersion'] = '{}'::jsonb
 AND jsonb_typeof(record->'Continuation'->'CommandID')='string'
 AND record->'Continuation'->>'CommandID' ~ '^[A-Za-z0-9_-]{21}[AQgw]$'
 AND jsonb_typeof(record->'Continuation'->'BeforeAuthorityVersion')='number'
 AND (record->'Continuation'->>'BeforeAuthorityVersion')::numeric BETWEEN 1 AND 18446744073709551614
 AND trunc((record->'Continuation'->>'BeforeAuthorityVersion')::numeric)=(record->'Continuation'->>'BeforeAuthorityVersion')::numeric
 AND jsonb_typeof(record->'Continuation'->'BeforeCredentialVersion')='number'
 AND (record->'Continuation'->>'BeforeCredentialVersion')::numeric BETWEEN 1 AND 18446744073709551614
 AND trunc((record->'Continuation'->>'BeforeCredentialVersion')::numeric)=(record->'Continuation'->>'BeforeCredentialVersion')::numeric
 AND (record->'Authority'->'Credential'->>'Version')::numeric=(record->'Continuation'->>'BeforeAuthorityVersion')::numeric+1
 AND (record->'Authentication'->>'CredentialVersion')::numeric BETWEEN 1 AND (record->'Continuation'->>'BeforeCredentialVersion')::numeric)) IS TRUE);
`
