package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PasswordRegistrationMigrationSource appends immutable original-command domain
// evidence, not a second command journal. Allocate Version after every Base
// migration, including credential references and identifier retirements. The
// binding survives payload pruning and proves only the exact original effect.
// Load performs no SQL; apply with the owned migrations Runner. Zero denies.
type PasswordRegistrationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves complete Base bytes and existing populated state; it returns
// independently owned forward-only history. Earlier cancellation wins. No
// destructive downgrade, implicit backfill or inferred existing signup occurs.
func (s PasswordRegistrationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidPasswordRegistration()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidPasswordRegistration()
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalidPasswordRegistration()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_password_registration_bindings", migrations.TransactionModeDefault, passwordRegistrationSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const passwordRegistrationSchemaSQL = `CREATE TABLE identity.registration_bindings (
 tenant_id identity.directory_id NOT NULL,
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.password.signup'),
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 user_id identity.directory_id NOT NULL,
 identifier_id identity.directory_id NOT NULL,
 credential_id identity.directory_id NOT NULL,
 PRIMARY KEY(tenant_id,purpose,command_id),
 UNIQUE(tenant_id,user_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
`

var _ migrations.Source = PasswordRegistrationMigrationSource{}
