package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// UsernameRegistrationMigrationSource extends original registration and email
// verification custody without changing installed rows or migration checksums.
// Base must contain registration, acceptance and email-verification histories.
// If selected, install the historical magic-link suffix before this successor;
// this suffix retains that constraint arm even when it was not selected. No
// magic-link or username workflow is activated by storage installation alone.
// Normalization binding remains an independently selected prerequisite.
type UsernameRegistrationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns copied forward-only history; it owns no database or runner.
func (s UsernameRegistrationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := func() error { return identity.InvalidInputError{Field: "username_registration"} }
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
	for _, previous := range history {
		if previous.Version() >= s.Version {
			return nil, invalid()
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_username_registration", migrations.TransactionModeDefault, usernameRegistrationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

// Only known predecessor constraints are replaced. Existing disposition and
// foreign-key evidence remain authoritative; no row or origin is inferred.
const usernameRegistrationSQL = `ALTER TABLE identity.registration_bindings
 DROP CONSTRAINT IF EXISTS registration_bindings_purpose_check,
 DROP CONSTRAINT IF EXISTS identity_registration_purpose_v2,
 DROP CONSTRAINT IF EXISTS identity_registration_disposition,
 DROP CONSTRAINT IF EXISTS identity_registration_disposition_v2,
 ADD CONSTRAINT identity_registration_purpose_v3 CHECK (
  purpose IN ('identity.password.signup','identity.username.signup','identity.magic-link.consume')
 ),
 ADD CONSTRAINT identity_registration_disposition_v3 CHECK (
  (purpose IN ('identity.password.signup','identity.username.signup') AND (
   (accepted_only AND user_id IS NULL AND identifier_id IS NULL AND credential_id IS NULL)
   OR (NOT accepted_only AND user_id IS NOT NULL AND identifier_id IS NOT NULL AND credential_id IS NOT NULL)
  ))
  OR (purpose='identity.magic-link.consume' AND NOT accepted_only
   AND user_id IS NOT NULL AND identifier_id IS NOT NULL AND credential_id IS NULL)
 );
ALTER TABLE identity.email_verifications
 DROP CONSTRAINT email_verifications_registration_purpose_check,
 ADD CONSTRAINT identity_email_registration_purpose_v2 CHECK (
  registration_purpose IN ('identity.password.signup','identity.username.signup')
 );
`

var _ migrations.Source = UsernameRegistrationMigrationSource{}
