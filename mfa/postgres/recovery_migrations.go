package mfapostgres

import (
	"context"
	"math"
	"reflect"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// RecoveryMigrationSource appends pending/active recovery sets and digest-only
// single-use codes after the owned TOTP factor history. Version is a permanent
// allocation in that namespace. Existing rows/history bytes are preserved and
// never backfilled into recovery authority. Activation remains a separate
// protected transition; pending codes cannot satisfy a recovery operation.
type RecoveryMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independently owned forward-only history without IO. Missing,
// invalid or conflicting history and cancellation use the existing owned
// migration-source contract. No destructive down migration is provided.
func (s RecoveryMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidAuthority()
	}
	v := reflect.ValueOf(s.Base)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Func, reflect.Slice, reflect.Chan:
		if v.IsNil() {
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
	next, err := migrations.NewMigration(s.Version, "identity_mfa_recovery_sets", migrations.TransactionModeDefault, recoverySetSQL, "")
	if err != nil {
		return nil, invalidAuthority()
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const recoverySetSQL = `ALTER TABLE identity_mfa.totp_factors
 ADD CONSTRAINT totp_factor_subject_unique UNIQUE(tenant_id,user_id,factor_id);
CREATE TABLE identity_mfa.recovery_sets (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 set_id text COLLATE "C" NOT NULL CHECK(set_id ~ '^[A-Za-z0-9_-]{22}$'),
 factor_id text COLLATE "C" NOT NULL,
 set_version identity.version NOT NULL,
 row_version identity.version NOT NULL,
 state smallint NOT NULL CHECK(state BETWEEN 1 AND 3),
 code_count smallint NOT NULL CHECK(code_count BETWEEN 1 AND 64),
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 created_command_id bytea NOT NULL CHECK(octet_length(created_command_id)=16),
 created_purpose text COLLATE "C" NOT NULL CHECK(created_purpose IN('identity.mfa.enable','identity.mfa.recovery-regenerate')),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 PRIMARY KEY(tenant_id,set_id),
 UNIQUE(tenant_id,created_purpose,created_command_id),
 FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES identity_mfa.totp_factors(tenant_id,user_id,factor_id),
 FOREIGN KEY(tenant_id,created_purpose,created_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
CREATE TABLE identity_mfa.recovery_codes (
 tenant_id identity.directory_id NOT NULL,
 set_id text COLLATE "C" NOT NULL,
 code_index smallint NOT NULL CHECK(code_index BETWEEN 0 AND 63),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 consumed_command_id bytea CHECK(octet_length(consumed_command_id)=16),
 consumed_purpose text COLLATE "C" CHECK(consumed_purpose='identity.mfa.recovery-use'),
 consumed_at timestamptz CHECK(isfinite(consumed_at)),
 PRIMARY KEY(tenant_id,set_id,code_index),
 UNIQUE(tenant_id,set_id,digest),
 FOREIGN KEY(tenant_id,set_id) REFERENCES identity_mfa.recovery_sets(tenant_id,set_id),
 FOREIGN KEY(tenant_id,consumed_purpose,consumed_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK(num_nonnulls(consumed_command_id,consumed_purpose,consumed_at) IN(0,3))
);
CREATE INDEX mfa_recovery_subject ON identity_mfa.recovery_sets(tenant_id,user_id,set_id);
`
