package reference

import (
	"context"
	"maps"
	"slices"

	identity "github.com/faustbrian/go-identity"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Reuse installed physical namespaces and owner SQL. In particular, install the
// common action predecessor once: later username selection must not rerun an
// older CHECK that removes phone consumption from a populated deployment.
func (s StoreSet) phoneMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.phone == nil {
		return catalog, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_phone_migrations"}
	if ctx == nil || len(catalog) == 0 {
		return nil, invalid
	}
	catalog, err := identifierMutationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = emailOTPFactorMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	// Email's installed password prefix is shared by all protected actions.
	// Retain it now so enabling email later cannot overwrite phone's CHECK.
	prefix, err := (passwordpg.EmailReauthenticationMigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_password" })
	if index < 0 {
		return nil, invalid
	}
	h := catalog[index]
	for i := 0; i < min(len(h.history), len(prefix)); i++ {
		if h.history[i] != prefix[i] {
			return nil, invalid
		}
	}
	if len(h.history) < len(prefix) {
		h.owners = maps.Clone(h.owners)
		h.history = append(slices.Clone(h.history), prefix[len(h.history):]...)
		for _, step := range prefix {
			h.owners[step.Version()] = "identity/password/postgres"
		}
		catalog[index] = h
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
	appendLast := func(namespace string, owner ModuleID, source migrations.Source, guard migrationGuard) ([]migrations.Migration, error) {
		steps, err := source.Load(ctx)
		if err != nil {
			return nil, err
		}
		step := steps[len(steps)-1]
		catalog = append(catalog, migrationHistory{namespace: namespace, history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{step.Version(): owner}, guards: []migrationGuard{guard}})
		return steps, nil
	}
	if !present("identity_username_kernel") {
		_, err = appendLast("identity_username_kernel", "identity/postgres", kernel.IdentifierNormalizationMigrationSource{Base: fixedMigrationSource(kernelHistory), Version: 1800}, migrationGuard{version: 1800, schema: "identity", columns: []string{"identifiers.normalization_profile", "identifiers.normalization_version"}})
		if err != nil {
			return nil, err
		}
	}
	if !present("identity_username_actions") {
		passwordHistory, err = appendLast("identity_username_actions", "identity/password/postgres", passwordpg.ActionReauthenticationMigrationSource{Base: fixedMigrationSource(passwordHistory), Version: 21}, migrationGuard{version: 21, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.username.update"})
		if err != nil {
			return nil, err
		}
	}
	_, err = appendLast("identity_phone_password", "identity/password/postgres", passwordpg.PhoneReauthenticationMigrationSource{Base: fixedMigrationSource(passwordHistory), Version: 23}, migrationGuard{version: 23, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.phone.send-verification"})
	if err != nil {
		return nil, err
	}
	_, err = appendLast("identity_phone_otp", "identity/otp/postgres", otppg.PhonePurposeMigrationSource{Schema: s.state.features.migrations.otpSchema, Version: 1}, migrationGuard{version: 1, schema: s.state.features.migrations.otpSchema, constraints: []string{"challenges.challenges_purpose_v2"}, constraintValue: "phone-verification"})
	if err != nil {
		return nil, err
	}
	return catalog, nil
}
