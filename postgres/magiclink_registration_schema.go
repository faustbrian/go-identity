package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// MagicLinkRegistrationMigrationSource extends existing registration evidence
// for passwordless creation under the original magic-link consume command.
// Base must install PasswordRegistrationMigrationSource and its acceptance
// suffix. Version must follow Base. This installs storage, not signup policy,
// email-possession authority or permission to create an identity.
type MagicLinkRegistrationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves old history and returns a forward-only suffix without SQL IO.
func (s MagicLinkRegistrationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := func() error { return identity.InvalidInputError{Field: "magiclink_registration"} }
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalid()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalid()
	}
	for _, old := range history {
		if old.Version() >= s.Version {
			return nil, invalid()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_magiclink_registration_bindings", migrations.TransactionModeDefault, magicLinkRegistrationSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

// Retain the password creation and neutral-acceptance arms exactly. A magic-link
// creation has no password credential; omitting it is not a neutral acceptance.
// Existing command-linked evidence owns recovery; no second journal is added.
const magicLinkRegistrationSchemaSQL = `ALTER TABLE identity.registration_bindings
 DROP CONSTRAINT registration_bindings_purpose_check,
 ADD CONSTRAINT identity_registration_purpose_v2 CHECK (
  purpose IN ('identity.password.signup','identity.magic-link.consume')
 ),
 DROP CONSTRAINT identity_registration_disposition,
 ADD CONSTRAINT identity_registration_disposition_v2 CHECK (
  (purpose='identity.password.signup' AND (
   (accepted_only AND user_id IS NULL AND identifier_id IS NULL AND credential_id IS NULL)
   OR (NOT accepted_only AND user_id IS NOT NULL AND identifier_id IS NOT NULL AND credential_id IS NOT NULL)
  ))
  OR (purpose='identity.magic-link.consume' AND NOT accepted_only
   AND user_id IS NOT NULL AND identifier_id IS NOT NULL AND credential_id IS NULL)
 );
`

var _ migrations.Source = MagicLinkRegistrationMigrationSource{}
