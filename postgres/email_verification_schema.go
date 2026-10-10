package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// EmailVerificationMigrationSource appends retained command-linked verification
// evidence to explicit Base history containing registration bindings. Existing
// bytes and populated accounts remain unchanged. Allocate Version after all
// selected histories; Load performs no IO. Apply through the migration runner.
// Evidence follows command-tombstone retention, not bearer or address retention.
type EmailVerificationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns owned forward-only history. Nil, colliding or out-of-range
// configuration denies; cancellation is preserved and no down SQL is supplied.
func (s EmailVerificationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidEmailVerification()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidEmailVerification()
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalidEmailVerification()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_email_verifications", migrations.TransactionModeDefault, emailVerificationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const emailVerificationSQL = `CREATE TABLE identity.email_verifications (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 identifier_id identity.directory_id NOT NULL,
 command_id text COLLATE "C" PRIMARY KEY CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$'),
 command_key bytea NOT NULL CHECK(octet_length(command_key)=16),
 registration_command_key bytea NOT NULL CHECK(octet_length(registration_command_key)=16),
 purpose text COLLATE "C" NOT NULL DEFAULT 'identity.email.verification-confirm' CHECK(purpose='identity.email.verification-confirm'),
 registration_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.password.signup' CHECK(registration_purpose='identity.password.signup'),
 before_user_version identity.version NOT NULL,
 after_user_version identity.version NOT NULL CHECK(after_user_version=before_user_version+1),
 before_authority_version identity.version NOT NULL,
 after_authority_version identity.version NOT NULL CHECK(after_authority_version=before_authority_version+1),
 verified_at timestamptz NOT NULL CHECK(isfinite(verified_at) AND verified_at >= '0001-01-01 00:00:00+00'::timestamptz AND verified_at < '10000-01-01 00:00:00+00'::timestamptz),
 FOREIGN KEY(tenant_id,purpose,command_key) REFERENCES identity.commands(tenant_id,purpose,command_id),
 FOREIGN KEY(tenant_id,registration_purpose,registration_command_key) REFERENCES identity.registration_bindings(tenant_id,purpose,command_id)
);
`
