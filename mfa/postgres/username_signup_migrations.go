package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// UsernameSignupMigrationSource adds exact username-signup initialization
// provenance. Base installs factor authorities and any selected historical
// magic-link suffix; Version follows all Base versions. This successor retains
// both prior purpose arms and changes no factor/account row. It never infers
// that an existing account has no enrolled factors.
type UsernameSignupMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load performs the same bounded immutable-history validation as the earlier
// signup suffix, replacing only its uninstalled last migration with this one.
func (s UsernameSignupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (MagicLinkSignupMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_username_signup", migrations.TransactionModeDefault, usernameSignupSQL, "")
	if err != nil {
		return nil, invalidAuthority()
	}
	history[len(history)-1] = forward
	return history, nil
}

const usernameSignupSQL = `ALTER TABLE identity_mfa.factor_authorities
 DROP CONSTRAINT IF EXISTS factor_authorities_initialized_purpose_check,
 DROP CONSTRAINT IF EXISTS factor_authorities_initialized_purpose_v2,
 ADD CONSTRAINT factor_authorities_initialized_purpose_v3 CHECK (
  initialized_purpose IN ('identity.password.signup','identity.magic-link.consume','identity.username.signup')
 );
`
