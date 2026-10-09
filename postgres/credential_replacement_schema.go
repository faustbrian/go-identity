package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// CredentialReplacementMigrationSource appends retained password-change effect
// evidence after explicitly allocated Base history containing credential rows.
// Existing migration bytes are unchanged. Apply with the owned migration runner;
// Load performs no IO. Retain evidence with command tombstones, not credential
// payloads: an absent effect is used for pending-command negative recovery.
// Missing infrastructure must remain unknown. Zero composition is invalid.
type CredentialReplacementMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns owned forward-only history. Invalid/colliding versions return no
// partial history, cancellation is preserved, and destructive down SQL is absent.
func (s CredentialReplacementMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidCredentialReplacement()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidCredentialReplacement()
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalidCredentialReplacement()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_credential_replacements", migrations.TransactionModeDefault, credentialReplacementSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const credentialReplacementSQL = `CREATE TABLE identity.credential_replacements (
 command_id text COLLATE "C" PRIMARY KEY CHECK (command_id ~ '^[A-Za-z0-9_-]{22}$'),
 command_key bytea NOT NULL CHECK (octet_length(command_key)=16),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 credential_id identity.directory_id NOT NULL,
 operation text COLLATE "C" NOT NULL CHECK (operation='identity.password.change'),
 before_user_version identity.version NOT NULL,
 after_user_version identity.version NOT NULL CHECK (after_user_version=before_user_version+1),
 before_authority_version identity.version NOT NULL,
 after_authority_version identity.version NOT NULL CHECK (after_authority_version=before_authority_version+1),
 before_credential_version identity.version NOT NULL,
 after_credential_version identity.version NOT NULL CHECK (after_credential_version=before_credential_version+1),
 FOREIGN KEY(tenant_id,user_id,credential_id) REFERENCES identity.credential_references(tenant_id,user_id,credential_id),
 FOREIGN KEY(tenant_id,operation,command_key) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
`
