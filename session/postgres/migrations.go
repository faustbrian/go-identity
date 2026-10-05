// Package postgres owns durable session storage. Structural record reads do
// not authenticate a bearer or authorize a session. Native family revocation
// and explicitly configured authenticated issuance use the sole coordinator.
// Complete bearer delivery, rotation and session authentication remain in development.
package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MigrationSource owns the adapter's forward-only install. Schema selects an
// unoccupied dedicated namespace (not public/identity/pg_*); Version is the
// permanently assigned 1..MaxInt64 version in the composition's single history.
// Compose this source with the kernel history and the owned migrations Runner;
// the identity.users table must already exist. Never renumber an applied version.
// Zero is invalid. Load performs no IO and is safe for concurrent callers.
type MigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = MigrationSource{}

// Load returns independently owned immutable SQL, with no destructive down
// migration. Existing/unmanaged schema objects fail rather than being adopted.
// Nil contexts and invalid source values fail; cancellation is preserved.
func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(sessionSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_records", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// RevocationMigrationSource composes the unchanged base install and the native
// revocation install in the composition's single migration history. Version is
// a permanent allocation greater than Base.Version and no greater than MaxInt64.
// Never renumber applied versions. This separate source preserves the original
// MigrationSource contract, including positional literals. Load performs no IO
// and is safe for concurrent callers; no destructive down migration is supplied.
type RevocationMigrationSource struct {
	Base    MigrationSource
	Version migrations.Version
}

var _ migrations.Source = RevocationMigrationSource{}

// Load returns the independently owned base history followed by the revocation
// migration. Invalid allocations and nil contexts fail; cancellation is preserved.
func (s RevocationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_migration"}
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(sessionMutationSchemaSQL, "@schema@", pgx.Identifier{s.Base.Schema}.Sanitize())
	mutation, err := migrations.NewMigration(s.Version, "identity_session_revocations", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, mutation), nil
}

func validSchema(s string) bool {
	if len(s) == 0 || len(s) > 63 || s == "public" || s == "identity" || s == "information_schema" || strings.HasPrefix(s, "pg_") {
		return false
	}
	for i := range len(s) {
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] == '_' || i > 0 && s[i] >= '0' && s[i] <= '9') {
			return false
		}
	}
	return true
}

// Fixed-width UTC nanosecond text retains the native timeline exactly, with
// bytewise chronological expiry indexes; timestamptz would round nanoseconds.
// Domain numerics reject fractions instead of rounding before CHECK execution.
const sessionSchemaSQL = `CREATE SCHEMA @schema@;
CREATE DOMAIN @schema@.scope_id AS text COLLATE "C"
 CHECK(VALUE ~ '^[!-~]{1,128}$');
CREATE DOMAIN @schema@.version AS numeric
 CHECK(VALUE>=1 AND VALUE<=18446744073709551615 AND scale(VALUE)=0);
CREATE DOMAIN @schema@.instant AS text COLLATE "C"
 CHECK(VALUE ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}Z$'
 AND isfinite(VALUE::timestamptz));
CREATE TABLE @schema@.families(
 tenant_id @schema@.scope_id NOT NULL,
 family_id @schema@.scope_id NOT NULL,
 user_id @schema@.scope_id NOT NULL,
 version @schema@.version NOT NULL,
 state text COLLATE "C" NOT NULL CHECK(state IN('active','revoked')),
 issued_at @schema@.instant NOT NULL,
 PRIMARY KEY(tenant_id,family_id),
 UNIQUE(tenant_id,family_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE TABLE @schema@.sessions(
 tenant_id @schema@.scope_id NOT NULL,
 session_id @schema@.scope_id NOT NULL,
 user_id @schema@.scope_id NOT NULL,
 family_id @schema@.scope_id NOT NULL,
 version @schema@.version NOT NULL,
 family_version @schema@.version NOT NULL,
 state text COLLATE "C" NOT NULL CHECK(state IN('active','revoked')),
 digest_version bigint NOT NULL CHECK(digest_version BETWEEN 1 AND 4294967295),
 digest bytea NOT NULL CHECK(octet_length(digest)=32 AND digest<>decode(repeat('00',32),'hex')),
 expires_at @schema@.instant NOT NULL,
 record jsonb NOT NULL CHECK(jsonb_typeof(record)='object' AND octet_length(record::text)<=32768),
 PRIMARY KEY(tenant_id,session_id),
 UNIQUE(tenant_id,digest_version,digest),
 FOREIGN KEY(tenant_id,family_id,user_id) REFERENCES @schema@.families(tenant_id,family_id,user_id),
 CHECK(record ?& ARRAY['Schema','SessionID','FamilyID','TenantID','UserID','Audience','Version','FamilyVersion','Remember','Authority','Lookup','Authentication','IssuedAt','LastActivityAt']),
 CHECK((record->>'Schema'='1' AND record->>'TenantID'=tenant_id
 AND record->>'SessionID'=session_id AND record->>'UserID'=user_id
 AND record->>'FamilyID'=family_id AND (record->>'Version')::numeric=version
 AND (record->>'FamilyVersion')::numeric=family_version) IS TRUE)
);
CREATE INDEX session_owner_order ON @schema@.sessions(tenant_id,user_id,session_id);
CREATE INDEX session_family_order ON @schema@.sessions(tenant_id,family_id,session_id);
CREATE INDEX session_expiry_order ON @schema@.sessions(expires_at,tenant_id,session_id) WHERE state='active';
`

// Retain the exact mutation binding independently of prunable session payloads.
// No adapter cleanup deletes it. The scoped journal FK prevents its command
// authority being retired while retained participant evidence still depends on it.
const sessionMutationSchemaSQL = `CREATE TABLE @schema@.family_revocations(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.session.revoke-family'),
 user_id @schema@.scope_id NOT NULL,
 family_id @schema@.scope_id NOT NULL,
 before_version @schema@.version NOT NULL,
 after_version @schema@.version NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose),
 CHECK(after_version=before_version+1)
);
`
