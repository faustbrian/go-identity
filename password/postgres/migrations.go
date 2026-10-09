package passwordpostgres

import (
	"context"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MigrationSource is immutable forward-only owned password history. Its zero
// value is usable; Load performs no IO. Install after the kernel credential
// history, in the permanently distinct identity_password migration namespace.
// Existing unmanaged schema objects fail instead of being silently adopted.
// The owned migrations Runner provides transaction/replay/receipt semantics.
type MigrationSource struct{}

var _ migrations.Source = MigrationSource{}

// Load supplies password material storage without destructive downgrade SQL.
// Hash encodings retain algorithm parameters; no plaintext, salts stored apart
// from their reviewed encoding, bearer or recoverable passwords are introduced.
func (MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil {
		return nil, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	migration, err := migrations.NewMigration(1, "identity_password_material", migrations.TransactionModeDefault, schemaSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return []migrations.Migration{migration}, nil
}

const schemaSQL = `CREATE SCHEMA identity_password;
CREATE TABLE identity_password.credentials (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 credential_id identity.directory_id NOT NULL,
 version identity.version NOT NULL,
 algorithm text COLLATE "C" NOT NULL CHECK(algorithm IN ('argon2id','bcrypt')),
 encoded_hash text COLLATE "C" NOT NULL CHECK(octet_length(encoded_hash) BETWEEN 1 AND 16384),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(tenant_id,user_id),
 FOREIGN KEY(tenant_id,user_id,credential_id) REFERENCES identity.credential_references(tenant_id,user_id,credential_id),
 CHECK(isfinite(created_at) AND created_at>='0001-01-01 00:00:00+00'::timestamptz AND created_at<'10000-01-01 00:00:00+00'::timestamptz),
 CHECK(isfinite(updated_at) AND updated_at>=created_at AND updated_at<'10000-01-01 00:00:00+00'::timestamptz)
);
`
