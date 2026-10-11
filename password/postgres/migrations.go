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
	replacement, err := migrations.NewMigration(2, "identity_password_replacement_effects", migrations.TransactionModeDefault, replacementSchemaSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	reauthentication, err := migrations.NewMigration(3, "identity_password_reauthentication_records", migrations.TransactionModeDefault, reauthenticationSchemaSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	consumption, err := migrations.NewMigration(4, "identity_password_reauthentication_consumption", migrations.TransactionModeDefault, reauthenticationConsumptionSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	signin, err := migrations.NewMigration(5, "identity_password_signin_records", migrations.TransactionModeDefault, signinSchemaSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	reset, err := migrations.NewMigration(6, "identity_password_reset_material_effects", migrations.TransactionModeDefault, resetMaterialSchemaSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return []migrations.Migration{migration, replacement, reauthentication, consumption, signin, reset}, nil
}

// Preserve installed checksums and populated change receipts. Reset shares the
// original material-effect owner, rather than adding a second intent journal.
const resetMaterialSchemaSQL = `ALTER TABLE identity_password.replacements
 DROP CONSTRAINT replacements_purpose_check,
 ADD CONSTRAINT replacements_purpose_check CHECK(purpose IN ('identity.password.change','identity.password.reset-complete'));
`

const signinSchemaSQL = `CREATE TABLE identity_password.signin_records (
 proof_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(proof_id) BETWEEN 22 AND 128),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.password.signin'),
 record bytea NOT NULL CHECK(octet_length(record) BETWEEN 1 AND 32768),
 UNIQUE(tenant_id,purpose,command_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
`

const reauthenticationConsumptionSQL = `ALTER TABLE identity_password.reauthentication_records
 ADD COLUMN consumed_command_id bytea,
 ADD COLUMN consumed_purpose text COLLATE "C",
 ADD COLUMN consumed_at timestamptz,
 ADD CONSTRAINT reauthentication_consumption_complete CHECK (
  (consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL)
  OR (consumed_command_id IS NOT NULL AND octet_length(consumed_command_id)=16
   AND consumed_purpose IS NOT NULL AND consumed_purpose='identity.password.change'
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz)),
 ADD CONSTRAINT reauthentication_consumption_command FOREIGN KEY(tenant_id,consumed_purpose,consumed_command_id)
 REFERENCES identity.commands(tenant_id,purpose,command_id);
CREATE UNIQUE INDEX reauthentication_consumption_once ON identity_password.reauthentication_records(tenant_id,consumed_purpose,consumed_command_id) WHERE consumed_command_id IS NOT NULL;
`

const reauthenticationSchemaSQL = `CREATE TABLE identity_password.reauthentication_records (
 proof_id text COLLATE "C" PRIMARY KEY CHECK(octet_length(proof_id) BETWEEN 22 AND 128),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.password.verify'),
 record bytea NOT NULL CHECK(octet_length(record) BETWEEN 1 AND 32768),
 UNIQUE(tenant_id,purpose,command_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
`

const replacementSchemaSQL = `CREATE TABLE identity_password.replacements (
 tenant_id identity.directory_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.password.change'),
 user_id identity.directory_id NOT NULL,
 credential_id identity.directory_id NOT NULL,
 before_version identity.version NOT NULL,
 after_version identity.version NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK(after_version=before_version+1)
);
`

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
