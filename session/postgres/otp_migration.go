package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// OTPMigrationSource admits complete historical OTP session projections with
// optional synchronizer state. Allocate a permanent Version after the existing
// CSRFMigrationSource in the sole migration history; Schema must name that same
// owned namespace. Apply before OTP writes and upgrade relevant readers/writers:
// older binaries reject schemas3/4. Existing payloads and receipt hashes remain
// unchanged. This migration neither enables OTP authentication nor issues a
// session. Zero is invalid; Load performs no IO and owns no transaction.
type OTPMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only transactional migration. The migration runner
// owns locking, validation and commitment; malformed populated data aborts the
// complete upgrade. Invalid configuration is redacted and cancellation retained.
func (s OTPMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_otp_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_otp", migrations.TransactionModeDefault, strings.ReplaceAll(otpSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// Replace only the constraint installed by the preceding CSRF migration. No
// historical SQL is rewritten or unrecognized installation silently adopted.
// Strict semantic reconstruction remains in the bounded native record codec.
const otpSchemaSQL = `ALTER TABLE @schema@.sessions DROP CONSTRAINT session_record_binding_v2;
ALTER TABLE @schema@.sessions ADD CONSTRAINT session_record_binding_v3 CHECK((
 record->>'TenantID'=tenant_id AND record->>'SessionID'=session_id
 AND record->>'UserID'=user_id AND record->>'FamilyID'=family_id
 AND (record->>'Version')::numeric=version
 AND (record->>'FamilyVersion')::numeric=family_version
 AND ((record->>'Schema' IN ('1','2') AND NOT record ? 'OTP'
 AND record->'Authentication'->>'Kind' IN ('1','2'))
 OR (record->>'Schema' IN ('3','4')
 AND record->'Authentication'->>'Kind'='3'
 AND jsonb_typeof(record->'OTP')='object'
 AND record->'OTP' ?& ARRAY['CommandID','SendCommandID','ChallengeID','AttemptID','IdentifierID','IdentifierKind','IdentifierVersion','VerificationVersion','AuthenticatedAt','ValidUntil']
 AND (record->'OTP') - ARRAY['CommandID','SendCommandID','ChallengeID','AttemptID','IdentifierID','IdentifierKind','IdentifierVersion','VerificationVersion','AuthenticatedAt','ValidUntil'] = '{}'::jsonb
 AND jsonb_typeof(record->'OTP'->'CommandID')='string'
 AND jsonb_typeof(record->'OTP'->'SendCommandID')='string'
 AND jsonb_typeof(record->'OTP'->'ChallengeID')='string'
 AND jsonb_typeof(record->'OTP'->'AttemptID')='string'
 AND jsonb_typeof(record->'OTP'->'IdentifierID')='string'
 AND record->'OTP'->>'IdentifierKind' IN ('email','phone')
 AND jsonb_typeof(record->'OTP'->'AuthenticatedAt')='string'
 AND jsonb_typeof(record->'OTP'->'ValidUntil')='string'
 AND jsonb_typeof(record->'OTP'->'IdentifierVersion')='number'
 AND (record->'OTP'->>'IdentifierVersion')::numeric BETWEEN 1 AND 18446744073709551615
 AND trunc((record->'OTP'->>'IdentifierVersion')::numeric)=(record->'OTP'->>'IdentifierVersion')::numeric
 AND jsonb_typeof(record->'OTP'->'VerificationVersion')='number'
 AND (record->'OTP'->>'VerificationVersion')::numeric BETWEEN 1 AND 18446744073709551615
 AND trunc((record->'OTP'->>'VerificationVersion')::numeric)=(record->'OTP'->>'VerificationVersion')::numeric))
 AND ((record->>'Schema' IN ('1','3') AND NOT record ? 'CSRF')
 OR (record->>'Schema' IN ('2','4') AND jsonb_typeof(record->'CSRF')='object'
 AND jsonb_typeof(record->'CSRF'->'Binding')='object'
 AND record->'CSRF'->'Binding'->>'TenantID'=tenant_id
 AND record->'CSRF'->'Binding'->>'SessionID'=session_id
 AND (record->'CSRF'->'Binding'->>'SessionVersion')::numeric=version
 AND jsonb_typeof(record->'CSRF'->'KeyVersion')='number'
 AND (record->'CSRF'->>'KeyVersion')::numeric BETWEEN 1 AND 4294967295
 AND trunc((record->'CSRF'->>'KeyVersion')::numeric)=(record->'CSRF'->>'KeyVersion')::numeric
 AND jsonb_typeof(record->'CSRF'->'Digest')='array'
 AND jsonb_array_length(record->'CSRF'->'Digest')=32))) IS TRUE);
`
