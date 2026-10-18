package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// VerificationContinuationMigrationSource appends verification-origin MFA to
// installed continuation history. A selected Base requires Version after it;
// nil Base returns one independent suffix for an operator-owned namespace.
// Existing migration
// bytes, original scopes, attempt budgets and deadlines remain unchanged; no
// primary, challenge or session is backfilled or reinterpreted.
type VerificationContinuationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns a forward-only constraint extension without database access.
// Zero versions, nil contexts and selected empty/misordered bases fail closed.
func (s VerificationContinuationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil {
		return nil, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.Base == nil {
		forward, err := migrations.NewMigration(s.Version, "identity_mfa_verification_continuations", migrations.TransactionModeDefault, verificationContinuationSQL, "")
		if err != nil {
			return nil, err
		}
		return []migrations.Migration{forward}, nil
	}
	history, err := (ContinuationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_verification_continuations", migrations.TransactionModeDefault, verificationContinuationSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

const verificationContinuationSQL = `ALTER TABLE identity_mfa.continuations
 DROP CONSTRAINT continuations_origin_purpose_check,
 ADD CONSTRAINT continuations_origin_purpose_v2 CHECK(origin_purpose IN('identity.magic-link.consume','identity.password.signin','identity.email.verification-signin'));
`
