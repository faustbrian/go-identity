package mfapostgres

import (
	"context"
	"math"
	"reflect"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// TOTPFactorMigrationSource appends encrypted factor/enrollment and replay
// storage after existing MFA history. Allocate Version permanently in that
// namespace. It preserves existing bytes and performs no enrollment/backfill.
type TOTPFactorMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns forward-only SQL. Zero, typed-nil or empty/conflicting histories
// deny. The source owns no IO and is safe for concurrent calls with a safe Base.
func (s TOTPFactorMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_totp_factors", migrations.TransactionModeDefault, totpFactorSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

// Factor authority is locked before enrollment/factor rows. Replay changes
// advance row_version, not enrollment_version or the global factor generation.
// A pending enrollment is never an active factor; confirmed_at and replay state
// cannot be used to infer its closed state. Revocation erases encrypted custody.
const totpFactorSQL = `CREATE TABLE identity_mfa.totp_factors (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 factor_id text COLLATE "C" NOT NULL CHECK(factor_id ~ '^[A-Za-z0-9_-]{22}$'),
 state smallint NOT NULL CHECK(state BETWEEN 1 AND 3),
 enrollment_version identity.version NOT NULL,
 row_version identity.version NOT NULL,
 algorithm text COLLATE "C" NOT NULL CHECK(algorithm IN('SHA1','SHA256','SHA512')),
 digits smallint NOT NULL CHECK(digits BETWEEN 6 AND 10),
 period_seconds smallint NOT NULL CHECK(period_seconds BETWEEN 15 AND 120),
 skew_steps smallint NOT NULL CHECK(skew_steps BETWEEN 0 AND 2),
 issuer text NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 128 AND issuer=btrim(issuer) AND issuer !~ '[:[:cntrl:]]'),
 encrypted_secret bytea CHECK(octet_length(encrypted_secret) BETWEEN 1 AND 4096),
 last_step numeric(20,0) CHECK(last_step BETWEEN 0 AND 614891469123651722),
 reveal_consumed boolean NOT NULL DEFAULT false,
 created_command_id bytea NOT NULL CHECK(octet_length(created_command_id)=16),
 created_purpose text COLLATE "C" NOT NULL CHECK(created_purpose IN('identity.mfa.enable','identity.mfa.factor-update')),
 created_at timestamptz NOT NULL,
 enrollment_expires_at timestamptz NOT NULL CHECK(enrollment_expires_at>created_at AND enrollment_expires_at<=created_at+interval '15 minutes'),
 confirmed_at timestamptz,
 PRIMARY KEY(tenant_id,factor_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity_mfa.factor_authorities(tenant_id,user_id),
 FOREIGN KEY(tenant_id,created_purpose,created_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 UNIQUE(tenant_id,created_purpose,created_command_id),
 CHECK((state=1 AND encrypted_secret IS NOT NULL AND confirmed_at IS NULL AND last_step IS NULL) OR
       (state=2 AND encrypted_secret IS NOT NULL AND confirmed_at IS NOT NULL AND confirmed_at>=created_at AND confirmed_at<enrollment_expires_at) OR
       (state=3 AND encrypted_secret IS NULL AND last_step IS NULL))
);
CREATE INDEX mfa_pending_totp_expiry ON identity_mfa.totp_factors(enrollment_expires_at,tenant_id,factor_id) WHERE state=1;
`
