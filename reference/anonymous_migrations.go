package reference

import (
	"context"
	"slices"

	identity "github.com/faustbrian/go-identity"
	anonymouspg "github.com/faustbrian/go-identity/anonymous/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Anonymous extends the actual selected predecessor histories last. Every
// suffix retains native SQL and a permanent independent reference namespace;
// no installed prefix or live identifier/session is rewritten/adopted.
func (s StoreSet) anonymousMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.anonymous == nil {
		return catalog, nil
	}
	a := s.state.features.anonymous
	var err error
	catalog, err = identifierMutationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	if a.deletion != nil || a.upgrade != nil {
		catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
		if err != nil {
			return nil, err
		}
	}
	present := func(namespace string) bool {
		return slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == namespace })
	}
	owned := func(owner ModuleID) []migrations.Migration {
		var out []migrations.Migration
		for _, h := range catalog {
			for _, m := range h.history {
				if h.owners[m.Version()] == owner {
					out = append(out, m)
				}
			}
		}
		return out
	}
	appendSource := func(namespace string, owner ModuleID, source migrations.Source, guard migrationGuard) error {
		steps, err := source.Load(ctx)
		if err != nil {
			return err
		}
		step := steps[len(steps)-1]
		catalog = append(catalog, migrationHistory{namespace: namespace, history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{step.Version(): owner}, guards: []migrationGuard{guard}})
		return nil
	}
	if !present("identity_username_kernel") {
		if err := appendSource("identity_username_kernel", "identity/postgres", kernel.IdentifierNormalizationMigrationSource{Base: fixedMigrationSource(owned("identity/postgres")), Version: 1800}, migrationGuard{version: 1800, schema: "identity", columns: []string{"identifiers.normalization_profile", "identifiers.normalization_version"}}); err != nil {
			return nil, err
		}
	}
	if err := appendSource("identity_anonymous_kernel", "identity/postgres", kernel.AnonymousIdentityMigrationSource{Base: fixedMigrationSource(owned("identity/postgres")), Version: 2000}, migrationGuard{version: 2000, schema: "identity", tables: []string{"anonymous_creation_bindings"}, constraints: []string{"identifiers.identity_anonymous_placeholder_shape"}}); err != nil {
		return nil, err
	}
	if err := appendSource("identity_anonymous", "identity/anonymous/postgres", anonymouspg.MigrationSource{Schema: a.repository.Schema, Version: 1}, migrationGuard{version: 1, schema: a.repository.Schema, tables: []string{"subjects"}}); err != nil {
		return nil, err
	}
	// Native enum/flags describe only histories already selected for this same
	// physical session store; they neither select another login method nor
	// execute its earlier purpose extension again.
	predecessor := sessionpg.AnonymousAfterOTP
	switch {
	case present("identity_verification_mfa_session"):
		predecessor = sessionpg.AnonymousAfterVerificationMFA
	case present("identity_verification_signin_session"):
		predecessor = sessionpg.AnonymousAfterVerification
	case present("identity_magiclink_mfa_session"):
		predecessor = sessionpg.AnonymousAfterMFA
	case present("identity_magiclink_session"):
		predecessor = sessionpg.AnonymousAfterMagicLink
	case present("identity_registration_session"):
		predecessor = sessionpg.AnonymousAfterSignup
	case present("identity_password_session"):
		predecessor = sessionpg.AnonymousAfterPassword
	}
	issue := sessionpg.AnonymousSigninMigrationSource{Schema: a.sessions.Schema, Version: 1, Predecessor: predecessor, MFASignin: predecessor == sessionpg.AnonymousAfterVerification && present("identity_magiclink_mfa_session"), UsernameSignin: present("identity_username_session"), PhonePasswordSignin: present("identity_phone_signin_session"), PhoneOTPSignin: present("identity_phone_otp_signin_session")}
	if err := appendSource("identity_anonymous_session", "identity/session/postgres", issue, migrationGuard{version: 1, schema: a.sessions.Schema, constraints: []string{"session_issuances.session_issuances_purpose_anonymous_v1"}}); err != nil {
		return nil, err
	}
	if a.deletion != nil {
		if err := appendSource("identity_anonymous_disposal_kernel", "identity/postgres", kernel.AnonymousDisposalMigrationSource{Base: fixedMigrationSource(owned("identity/postgres")), Version: 2001}, migrationGuard{version: 2001, schema: "identity", tables: []string{"anonymous_disposals"}}); err != nil {
			return nil, err
		}
		if err := appendSource("identity_anonymous_disposal_session", "identity/session/postgres", sessionpg.AnonymousDisposalMigrationSource{Schema: a.sessions.Schema, Version: 1}, migrationGuard{version: 1, schema: a.sessions.Schema, tables: []string{"anonymous_disposals"}}); err != nil {
			return nil, err
		}
		if err := appendSource("identity_anonymous_disposal", "identity/anonymous/postgres", anonymouspg.DisposalMigrationSource{Schema: a.repository.Schema, Version: 1}, migrationGuard{version: 1, schema: a.repository.Schema, tables: []string{"disposals"}}); err != nil {
			return nil, err
		}
	}
	if a.upgrade != nil {
		if !present("identity_password") || !present("identity_capability") || !present("identity_mfa") {
			return nil, identity.InvalidInputError{Field: "reference_anonymous_upgrade_migrations"}
		}
		if !present("identity_username_actions") {
			if err := appendSource("identity_username_actions", "identity/password/postgres", passwordpg.ActionReauthenticationMigrationSource{Base: fixedMigrationSource(owned("identity/password/postgres")), Version: 21}, migrationGuard{version: 21, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.username.update"}); err != nil {
				return nil, err
			}
		}
		if err := appendSource("identity_anonymous_upgrade_kernel", "identity/postgres", kernel.AnonymousUpgradeDisposalMigrationSource{Base: fixedMigrationSource(owned("identity/postgres")), Version: 2002}, migrationGuard{version: 2002, schema: "identity", constraints: []string{"anonymous_disposals.anonymous_disposals_purpose_check"}, constraintValue: "identity.anonymous.upgrade"}); err != nil {
			return nil, err
		}
		if err := appendSource("identity_anonymous_upgrade_password", "identity/password/postgres", passwordpg.AnonymousUpgradeReauthenticationMigrationSource{Base: fixedMigrationSource(owned("identity/password/postgres")), Version: 30}, migrationGuard{version: 30, schema: "identity_password", constraintValue: "identity.anonymous.upgrade", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}}); err != nil {
			return nil, err
		}
		if err := appendSource("identity_anonymous_upgrade_session", "identity/session/postgres", sessionpg.AnonymousUpgradeMigrationSource{AnonymousSignin: issue, Version: 2}, migrationGuard{version: 2, schema: a.sessions.Schema, constraints: []string{"session_issuances.session_issuances_purpose_anonymous_upgrade_v1", "anonymous_disposals.anonymous_disposals_purpose_upgrade_v1"}}); err != nil {
			return nil, err
		}
		if err := appendSource("identity_anonymous_upgrade", "identity/anonymous/postgres", anonymouspg.UpgradeMigrationSource{Schema: a.repository.Schema, Version: 1}, migrationGuard{version: 1, schema: a.repository.Schema, tables: []string{"upgrades"}}); err != nil {
			return nil, err
		}
	}
	return catalog, nil
}
