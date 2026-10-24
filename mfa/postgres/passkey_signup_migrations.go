package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// PasskeySignupMigrationSource extends factor-initialization provenance for
// prospective passkey-only signup without backfilling any existing identity.
// Base installs factor authority and selected historical magic-link/username
// successors. Allocate Version after every Base version in the MFA namespace.
type PasskeySignupMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves predecessor bytes and populated state, performing no SQL IO.
// Missing prerequisite schema fails when applied; no downgrade is provided.
func (s PasskeySignupMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (MagicLinkSignupMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_passkey_signup", migrations.TransactionModeDefault, passkeySignupSQL, "")
	if err != nil {
		return nil, invalidAuthority()
	}
	history[len(history)-1] = forward
	return history, nil
}

const passkeySignupSQL = `ALTER TABLE identity_mfa.factor_authorities
 DROP CONSTRAINT IF EXISTS factor_authorities_initialized_purpose_check,
 DROP CONSTRAINT IF EXISTS factor_authorities_initialized_purpose_v2,
 DROP CONSTRAINT IF EXISTS factor_authorities_initialized_purpose_v3,
 ADD CONSTRAINT factor_authorities_initialized_purpose_v4 CHECK (
 initialized_purpose IN ('identity.password.signup','identity.magic-link.consume','identity.username.signup','identity.passkey.register-verify')
 );
`
