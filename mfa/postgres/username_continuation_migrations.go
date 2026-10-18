package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// UsernameContinuationMigrationSource appends the explicit username-origin
// continuation profile after password continuations. VerificationSignin selects
// the already installed verification-origin predecessor; a mismatched selection
// fails rather than dropping an unknown constraint or rewriting older history.
// Base is optional for an operator-owned suffix namespace; otherwise Version
// must follow it. Existing scopes, attempts, states and deadlines stay unchanged.
type UsernameContinuationMigrationSource struct {
	Base               migrations.Source
	Version            migrations.Version
	VerificationSignin bool
}

// Load returns copied forward-only history without database access or implicit
// predecessor discovery. No existing record is relabeled or made authenticated.
func (s UsernameContinuationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil {
		return nil, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	constraint := "continuations_origin_purpose_check"
	purposes := "'identity.magic-link.consume','identity.password.signin','identity.username.signin'"
	if s.VerificationSignin {
		constraint = "continuations_origin_purpose_v2"
		purposes += ",'identity.email.verification-signin'"
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_username_continuations", migrations.TransactionModeDefault,
		"ALTER TABLE identity_mfa.continuations DROP CONSTRAINT "+constraint+", ADD CONSTRAINT continuations_origin_purpose_username_v1 CHECK(origin_purpose IN("+purposes+"));\n", "")
	if err != nil {
		return nil, err
	}
	if s.Base == nil {
		return []migrations.Migration{forward}, nil
	}
	history, err := (ContinuationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}
