package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// PasskeyContinuationMigrationSource appends the selected native passkey-primary
// origin to the existing continuation table. Base must be nonempty and Version
// must follow it. Flags describe already installed predecessor profiles, not
// new opt-ins: selecting the wrong named predecessor fails during migration.
// Existing scopes, states, attempts and original deadlines remain unchanged.
type PasskeyContinuationMigrationSource struct {
	Base                                                            migrations.Source
	Version                                                         migrations.Version
	PasswordSignin, VerificationSignin, UsernameSignin, PhoneSignin bool
}

// Load returns copied forward-only history without database IO or implicit
// discovery. It never authenticates or backfills an existing continuation.
func (s PasskeyContinuationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (ContinuationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	constraint := "continuations_origin_purpose_check"
	purposes := "'identity.magic-link.consume','identity.passkey.signin-verify'"
	if s.PasswordSignin || s.VerificationSignin || s.UsernameSignin || s.PhoneSignin {
		purposes += ",'identity.password.signin'"
	}
	if s.VerificationSignin {
		constraint = "continuations_origin_purpose_v2"
		purposes += ",'identity.email.verification-signin'"
	}
	if s.UsernameSignin {
		constraint = "continuations_origin_purpose_username_v1"
		purposes += ",'identity.username.signin'"
	}
	if s.PhoneSignin {
		constraint = "continuations_origin_purpose_phone_v1"
		purposes += ",'identity.phone.password-signin'"
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_passkey_continuations", migrations.TransactionModeDefault,
		"ALTER TABLE identity_mfa.continuations DROP CONSTRAINT "+constraint+", ADD CONSTRAINT continuations_origin_purpose_passkey_v1 CHECK(origin_purpose IN("+purposes+"));\n", "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}
