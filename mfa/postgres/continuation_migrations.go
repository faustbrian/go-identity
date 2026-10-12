package mfapostgres

import (
	"context"
	"math"
	"reflect"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ContinuationMigrationSource appends durable partial-authentication state to
// the existing MFA history. Base must install factor authority after kernel
// users/commands. Allocate Version permanently after Base in its namespace.
// Existing factors and continuations are not inferred, reset or backfilled.
type ContinuationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves prior migration bytes and returns forward-only SQL without IO.
// Zero, typed-nil Base, empty history and conflicting version order deny.
func (s ContinuationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidAuthority()
	}
	value := reflect.ValueOf(s.Base)
	switch value.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan, reflect.Interface:
		if value.IsNil() {
			return nil, invalidAuthority()
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidAuthority()
	}
	for _, old := range history {
		if old.Version() >= s.Version {
			return nil, invalidAuthority()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_continuations", migrations.TransactionModeDefault, continuationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const continuationSQL = `CREATE TABLE identity_mfa.continuations (
 tenant_id identity.directory_id NOT NULL,
 continuation_id text COLLATE "C" NOT NULL CHECK(continuation_id ~ '^[A-Za-z0-9_-]{22}$'),
 user_id identity.directory_id NOT NULL,
 source_preauth_id text COLLATE "C" NOT NULL CHECK(source_preauth_id ~ '^[A-Za-z0-9_-]{22}$'),
 origin_command_id bytea NOT NULL CHECK(octet_length(origin_command_id)=16),
 origin_purpose text COLLATE "C" NOT NULL CHECK(origin_purpose='identity.magic-link.consume'),
 origin_fingerprint bytea NOT NULL CHECK(octet_length(origin_fingerprint)=32),
 origin_generation identity.version NOT NULL,
 scope_digest bytea NOT NULL CHECK(octet_length(scope_digest)=32),
 original_scope bytea NOT NULL CHECK(octet_length(original_scope) BETWEEN 1 AND 8192),
 state smallint NOT NULL CHECK(state BETWEEN 1 AND 5),
 version identity.version NOT NULL,
 max_attempts integer NOT NULL CHECK(max_attempts BETWEEN 1 AND 100),
 attempts_remaining integer NOT NULL CHECK(attempts_remaining BETWEEN 0 AND max_attempts),
 issued_at timestamptz NOT NULL CHECK(issued_at>to_timestamp(0) AND date_trunc('second',issued_at)=issued_at),
 expires_at timestamptz NOT NULL CHECK(date_trunc('second',expires_at)=expires_at AND expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 PRIMARY KEY(tenant_id,continuation_id),
 UNIQUE(tenant_id,origin_purpose,origin_command_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity_mfa.factor_authorities(tenant_id,user_id),
 FOREIGN KEY(tenant_id,origin_purpose,origin_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK((state=1 AND version=1 AND attempts_remaining=max_attempts) OR
       (state=2 AND version>=2 AND attempts_remaining BETWEEN 1 AND max_attempts-1) OR
       (state=3 AND version>=2 AND attempts_remaining<max_attempts) OR state IN(4,5))
);
CREATE INDEX mfa_continuation_expiry ON identity_mfa.continuations(expires_at,tenant_id,continuation_id) WHERE state IN(1,2);
`
