package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PasskeyRegistrationMigrationSource extends the existing original-command
// registration evidence for passkey-only creation. Base must include credential
// references, PasswordRegistrationMigrationSource and its acceptance suffix.
// Install selected historical magic-link/username suffixes before this forward
// successor. Their disposition arms and all populated rows remain intact; no
// workflow is enabled by the schema alone. Version follows every Base version.
type PasskeyRegistrationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns copied forward-only history without SQL IO or implicit backfill.
// Missing prerequisites are errors when the real migration is applied.
func (s PasskeyRegistrationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidPasskeyRegistration()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidPasskeyRegistration()
	}
	for _, old := range history {
		if old.Version() >= s.Version {
			return nil, invalidPasskeyRegistration()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_passkey_registration_bindings", migrations.TransactionModeDefault, passkeyRegistrationSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

// Only known predecessor checks change. Existing command foreign keys and
// unique subject custody stay authoritative; no prior success is inferred.
const passkeyRegistrationSchemaSQL = `ALTER TABLE identity.registration_bindings
 DROP CONSTRAINT IF EXISTS registration_bindings_purpose_check,
 DROP CONSTRAINT IF EXISTS identity_registration_purpose_v2,
 DROP CONSTRAINT IF EXISTS identity_registration_purpose_v3,
 DROP CONSTRAINT IF EXISTS identity_registration_disposition,
 DROP CONSTRAINT IF EXISTS identity_registration_disposition_v2,
 DROP CONSTRAINT IF EXISTS identity_registration_disposition_v3,
 ADD CONSTRAINT identity_registration_purpose_v4 CHECK (
  purpose IN ('identity.password.signup','identity.username.signup','identity.magic-link.consume','identity.passkey.register-verify')
 ),
 ADD CONSTRAINT identity_registration_disposition_v4 CHECK (
  (purpose IN ('identity.password.signup','identity.username.signup') AND (
   (accepted_only AND user_id IS NULL AND identifier_id IS NULL AND credential_id IS NULL)
   OR (NOT accepted_only AND user_id IS NOT NULL AND identifier_id IS NOT NULL AND credential_id IS NOT NULL)
  ))
  OR (purpose='identity.magic-link.consume' AND NOT accepted_only
   AND user_id IS NOT NULL AND identifier_id IS NOT NULL AND credential_id IS NULL)
  OR (purpose='identity.passkey.register-verify' AND NOT accepted_only
   AND user_id IS NOT NULL AND identifier_id IS NULL AND credential_id IS NOT NULL)
 );
`

var _ migrations.Source = PasskeyRegistrationMigrationSource{}
