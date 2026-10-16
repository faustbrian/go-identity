package reference

import (
	"context"

	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Select the real session-owned predecessor without enabling general magic-link
// login. This independent suffix never changes applied migration bytes.
func (s StoreSet) verificationSigninMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features.verificationSignin == nil {
		return catalog, nil
	}
	schema := s.state.features.migrations.passwordSigninSchema
	magic, mfa := false, false
	for _, h := range catalog {
		magic = magic || h.namespace == "identity_magiclink_session"
		mfa = mfa || h.namespace == "identity_magiclink_mfa_session"
	}
	if !magic {
		var err error
		catalog, err = magicLinkMigrationCatalog(ctx, catalog, schema)
		if err != nil {
			return nil, err
		}
	}
	steps, err := (sessionpg.EmailVerificationSigninMigrationSource{Schema: schema, Version: 1, MFASignin: mfa}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_verification_signin_session", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, tables: []string{"session_issuances_verification_parent_unique"}, columns: []string{"session_issuances.verification_command_id"}, constraints: []string{"session_issuances.session_issuances_purpose_v7", "session_issuances.session_issuances_verification_parent"}}}}), nil
}
