package reference

import (
	"context"
	"slices"

	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Phone OTP is the final selected provenance suffix. Reuse owner migrations,
// including the installed session predecessor, without changing prior SQL or
// selecting any password workflow merely to admit the new issuance purpose.
func (s StoreSet) phoneOTPSigninMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.phoneOTPSignin == nil {
		return catalog, nil
	}
	present := func(namespace string) bool {
		return slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == namespace })
	}
	if !present("identity_username_kernel") {
		var history []migrations.Migration
		for _, h := range catalog {
			for _, step := range h.history {
				if h.owners[step.Version()] == "identity/postgres" {
					history = append(history, step)
				}
			}
		}
		steps, err := (kernel.IdentifierNormalizationMigrationSource{Base: fixedMigrationSource(history), Version: 1800}).Load(ctx)
		if err != nil {
			return nil, err
		}
		step := steps[len(steps)-1]
		catalog = append(catalog, migrationHistory{namespace: "identity_username_kernel", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{1800: "identity/postgres"}, guards: []migrationGuard{{version: 1800, schema: "identity", columns: []string{"identifiers.normalization_profile", "identifiers.normalization_version"}}}})
	}
	schema := s.state.features.migrations.signinSchema
	if schema == "" {
		schema = s.state.features.migrations.passwordSigninSchema
	}
	if !present("identity_password_session") {
		steps, err := (sessionpg.PasswordSigninMigrationSource{Schema: schema, Version: 1}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_password_session", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_v3"}}}})
	}
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
	steps, err := (sessionpg.PhoneOTPSigninMigrationSource{Schema: schema, Version: 1, Predecessor: predecessor, MFASignin: predecessor == sessionpg.UsernameSigninAfterVerification && present("identity_magiclink_mfa_session"), UsernameSignin: present("identity_username_password"), PhonePasswordSignin: present("identity_phone_signin_session")}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_phone_otp_signin_session", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_phone_otp_v1"}}}}), nil
}
