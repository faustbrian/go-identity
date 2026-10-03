package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// CredentialMigrationSource composes immutable Base history with non-secret
// credential references and an independent user credential epoch. Version must
// be explicitly allocated after all Base versions and fit SQL migration storage.
// Existing MigrationSource and StatusMigrationSource history remains unchanged.
// Load performs no SQL; apply with the owned migrations Runner. The zero value
// is invalid. Destructive downgrade SQL is deliberately unavailable.
type CredentialMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

var _ migrations.Source = CredentialMigrationSource{}

// Load returns independently owned forward-only history. Migration defaults
// preserve existing status/aggregate/identifier epochs and old creation writers.
// Epoch 1 does not create a credential or grant authority: a missing reference
// still denies. References contain no secret/verifier; feature mutations must
// enlist through the sole coordinator rather than consumer SQL callbacks.
func (s CredentialMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "credential_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "credential_migration"}
	}
	for _, migration := range history {
		if migration.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "credential_migration"}
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_credential_references", migrations.TransactionModeDefault, credentialSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const credentialSchemaSQL = `ALTER TABLE identity.users
 ADD COLUMN credential_version identity.version NOT NULL DEFAULT 1;

CREATE TABLE identity.credential_references (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 credential_id identity.directory_id NOT NULL,
 kind smallint NOT NULL,
 owner text COLLATE "C" NOT NULL,
 version identity.version NOT NULL,
 enabled boolean NOT NULL,
 expires_at timestamptz,
 PRIMARY KEY(tenant_id,user_id,credential_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 CONSTRAINT identity_credential_owner CHECK (
  (kind=1 AND owner='identity/password') OR
  (kind=2 AND owner IN ('passkey','webauthn')) OR
  (kind=3 AND owner IN ('identity/oauth','sso')) OR
  (kind=4 AND owner='identity/apikey')),
 CONSTRAINT identity_credential_expiry CHECK (expires_at IS NULL OR
  (isfinite(expires_at) AND expires_at > '0001-01-01 00:00:00+00'::timestamptz
   AND expires_at < '10000-01-01 00:00:00+00'::timestamptz))
);
`
