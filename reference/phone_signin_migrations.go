package reference

import (
	"context"
	"slices"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Phone/password provenance is installed last, after every selected enrollment,
// username, verification and MFA suffix. Owner sources preserve all installed
// checksums and fail on a wrong predecessor instead of dropping unknown checks.
func (s StoreSet) phoneSigninMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.phoneSignin == nil {
		return catalog, nil
	}
	if len(catalog) == 0 {
		return nil, identity.InvalidInputError{Field: "reference_phone_signin_migrations"}
	}
	present := func(namespace string) bool {
		return slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == namespace })
	}
	var kernelHistory, passwordHistory []migrations.Migration
	for _, h := range catalog {
		for _, step := range h.history {
			switch h.owners[step.Version()] {
			case "identity/postgres":
				kernelHistory = append(kernelHistory, step)
			case "identity/password/postgres":
				passwordHistory = append(passwordHistory, step)
			}
		}
	}
	appendLast := func(namespace string, owner ModuleID, steps []migrations.Migration, guard migrationGuard) {
		step := steps[len(steps)-1]
		catalog = append(catalog, migrationHistory{namespace: namespace, history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{step.Version(): owner}, guards: []migrationGuard{guard}})
	}
	if !present("identity_username_kernel") {
		steps, err := (kernel.IdentifierNormalizationMigrationSource{Base: fixedMigrationSource(kernelHistory), Version: 1800}).Load(ctx)
		if err != nil {
			return nil, err
		}
		appendLast("identity_username_kernel", "identity/postgres", steps, migrationGuard{version: 1800, schema: "identity", columns: []string{"identifiers.normalization_profile", "identifiers.normalization_version"}})
	}
	username := present("identity_username_password")
	steps, err := (passwordpg.PhonePasswordSigninMigrationSource{Base: fixedMigrationSource(passwordHistory), Version: 24, UsernameSignin: username}).Load(ctx)
	if err != nil {
		return nil, err
	}
	appendLast("identity_phone_signin_password", "identity/password/postgres", steps, migrationGuard{version: 24, schema: "identity_password", constraints: []string{"signin_records.signin_records_purpose_phone_v1"}})
	predecessor := sessionpg.UsernameSigninAfterPassword
	switch {
	case present("identity_verification_mfa_session"):
		predecessor = sessionpg.UsernameSigninAfterVerificationMFA
	case present("identity_verification_signin_session"):
		predecessor = sessionpg.UsernameSigninAfterVerification
	case present("identity_magiclink_mfa_session"):
		predecessor = sessionpg.UsernameSigninAfterMFA
	case present("identity_magiclink_session"):
		predecessor = sessionpg.UsernameSigninAfterMagicLink
	case present("identity_registration_session"):
		predecessor = sessionpg.UsernameSigninAfterSignup
	}
	schema := s.state.features.migrations.passwordSigninSchema
	steps, err = (sessionpg.PhonePasswordSigninMigrationSource{Schema: schema, Version: 1, Predecessor: predecessor, MFASignin: predecessor == sessionpg.UsernameSigninAfterVerification && present("identity_magiclink_mfa_session"), UsernameSignin: username}).Load(ctx)
	if err != nil {
		return nil, err
	}
	appendLast("identity_phone_signin_session", "identity/session/postgres", steps, migrationGuard{version: 1, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_phone_password_v1"}})
	return catalog, nil
}
