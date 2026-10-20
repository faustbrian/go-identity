package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhoneContinuationMigrationSource adds the explicitly selected phone-password
// origin to the existing non-final continuation store. Allocate Version after
// Base. UsernameSignin and VerificationSignin describe the installed predecessor;
// selecting a different constraint fails at migration rather than dropping an
// unknown constraint. Scope, factor, attempt, replay and expiry records are not
// changed or backfilled. Construction and Load perform no database operations.
type PhoneContinuationMigrationSource struct {
	Base                               migrations.Source
	Version                            migrations.Version
	UsernameSignin, VerificationSignin bool
}

// Load returns copied forward-only history. Base must be nonempty and Version
// must follow it; nil, cancellation, invalid bounds and ordering fail closed.
func (s PhoneContinuationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (ContinuationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	constraint := "continuations_origin_purpose_check"
	purposes := "'identity.magic-link.consume','identity.password.signin','identity.phone.password-signin'"
	if s.VerificationSignin {
		constraint = "continuations_origin_purpose_v2"
		purposes += ",'identity.email.verification-signin'"
	}
	if s.UsernameSignin {
		constraint = "continuations_origin_purpose_username_v1"
		purposes += ",'identity.username.signin'"
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_phone_continuations", migrations.TransactionModeDefault,
		"ALTER TABLE identity_mfa.continuations DROP CONSTRAINT "+constraint+", ADD CONSTRAINT continuations_origin_purpose_phone_v1 CHECK(origin_purpose IN("+purposes+"));\n", "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}
