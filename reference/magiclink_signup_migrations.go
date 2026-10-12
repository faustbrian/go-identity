package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Signup shares the registration prefix with password registration, without
// selecting its workflow or credential storage. Independent forward extensions
// preserve installed registration/MFA checksums and allow later TOTP selection.
func magicLinkSignupMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	registration, factors := -1, -1
	for i, h := range catalog {
		switch h.namespace {
		case "identity_registration":
			registration = i
		case "identity_mfa":
			factors = i
		}
	}
	if len(catalog) == 0 || factors < 0 {
		return nil, identity.InvalidInputError{Field: "reference_magic_link_signup_history"}
	}
	if registration < 0 {
		base := fixedMigrationSource(catalog[0].history)
		identifiers := kernel.IdentifierMutationMigrationSource{Base: base, Version: 1600}
		creation := kernel.PasswordRegistrationMigrationSource{Base: identifiers, Version: 1601}
		full, err := (kernel.PasswordSignupAcceptanceMigrationSource{Base: creation, Version: 1602}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_registration", history: full[len(catalog[0].history):], owners: map[migrations.Version]ModuleID{1600: "identity/postgres", 1601: "identity/postgres", 1602: "identity/postgres"}, guards: []migrationGuard{
			{version: 1600, schema: "identity", tables: []string{"identifier_retirements"}},
			{version: 1601, schema: "identity", tables: []string{"registration_bindings"}},
			{version: 1602, schema: "identity", columns: []string{"registration_bindings.accepted_only"}},
		}})
		registration = len(catalog) - 1
	}
	creation, err := (kernel.MagicLinkRegistrationMigrationSource{Base: fixedMigrationSource(catalog[registration].history), Version: 1604}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_magiclink_registration", history: creation[len(creation)-1:], owners: map[migrations.Version]ModuleID{1604: "identity/postgres"}, guards: []migrationGuard{{version: 1604, schema: "identity", constraints: []string{"registration_bindings.identity_registration_purpose_v2", "registration_bindings.identity_registration_disposition_v2"}}}})
	factor, err := (mfapg.MagicLinkSignupMigrationSource{Base: fixedMigrationSource(catalog[factors].history), Version: 4}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_magiclink_signup_factors", history: factor[len(factor)-1:], owners: map[migrations.Version]ModuleID{4: "identity/mfa/postgres"}, guards: []migrationGuard{{version: 4, schema: "identity_mfa", constraints: []string{"factor_authorities.factor_authorities_initialized_purpose_v2"}}}})
	return catalog, nil
}
