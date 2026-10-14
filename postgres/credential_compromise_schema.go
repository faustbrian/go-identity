package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// CredentialCompromiseMigrationSource adds retained kernel participant evidence
// after explicitly allocated Base history (including credential references).
// It changes no installed bytes. Load performs no SQL; the owned migration
// runner applies forward-only history. Retain evidence with command tombstones,
// never prune it with verifier/reference payloads: absence is negative recovery
// evidence. Missing infrastructure remains unknown, not proof of noncommit.
type CredentialCompromiseMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independently owned history; nil/invalid composition or colliding
// versions return no history. Cancellation is preserved; no down SQL is supplied.
func (s CredentialCompromiseMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidCredentialCompromise()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidCredentialCompromise()
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalidCredentialCompromise()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_credential_compromises", migrations.TransactionModeDefault, credentialCompromiseSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const credentialCompromiseSQL = `CREATE TABLE identity.credential_compromises (
 command_id text COLLATE "C" PRIMARY KEY CHECK (command_id ~ '^[A-Za-z0-9_-]{22}$'),
 command_key bytea NOT NULL CHECK (octet_length(command_key)=16),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 credential_id identity.directory_id NOT NULL,
 operation text COLLATE "C" NOT NULL,
 owner text COLLATE "C" NOT NULL,
 kind smallint NOT NULL,
 before_user_version identity.version NOT NULL,
 after_user_version identity.version NOT NULL CHECK (after_user_version=before_user_version+1),
 before_authority_version identity.version NOT NULL,
 after_authority_version identity.version NOT NULL CHECK (after_authority_version=before_authority_version+1),
 before_credential_version identity.version NOT NULL,
 after_credential_version identity.version NOT NULL CHECK (after_credential_version=before_credential_version+1),
 CHECK ((kind=1 AND owner='identity/password' AND operation='identity.password.mark-compromised') OR
        (kind=2 AND owner='passkey' AND operation='identity.passkey.mark-compromised')),
 FOREIGN KEY(tenant_id,user_id,credential_id) REFERENCES identity.credential_references(tenant_id,user_id,credential_id),
 FOREIGN KEY(tenant_id,operation,command_key) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
`
