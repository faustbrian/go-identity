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

// The native constraints extend their existing physical schemas. As with the
// other optional profiles, forward steps have separate permanent ledgers so a
// later independent feature cannot insert history behind an applied version.
// No SQL or predecessor checksums are copied or rewritten here.
func (s StoreSet) phonePasswordResetMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.phonePasswordReset == nil {
		return catalog, nil
	}
	if ctx == nil || len(catalog) == 0 {
		return nil, identity.InvalidInputError{Field: "reference_phone_password_reset_migrations"}
	}
	var err error
	catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	for _, h := range catalog {
		if h.namespace == "identity_mfa" && len(h.history) <= 6 {
			catalog, err = mfaEnrollmentMigrationCatalog(ctx, catalog, s.state.config.Schema)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	var directory []migrations.Migration
	for _, h := range catalog {
		for _, step := range h.history {
			if h.owners[step.Version()] == "identity/postgres" {
				directory = append(directory, step)
			}
		}
	}
	// Slot1902 follows the current normalization, registration and phone-change
	// allocations through1901. Its physical constraint needs the existing reset
	// predecessor selected by resetSchema, not another recovery service.
	full, err := (kernel.PhonePasswordResetMigrationSource{Base: fixedMigrationSource(directory), Version: 1902}).Load(ctx)
	if err != nil {
		return nil, err
	}
	kernelStep := full[len(full)-1]
	// Material purpose is independent of optional signin/reauthentication CHECKs.
	// Use the exact canonical material prefix; native Load verifies it through
	// the original reset migration. Slot27 follows existing optional slots21..26.
	full, err = (passwordpg.PhonePasswordResetMigrationSource{Base: passwordpg.MigrationSource{}, Version: 27}).Load(ctx)
	if err != nil {
		return nil, err
	}
	passwordStep := full[len(full)-1]
	schema := s.state.features.migrations.resetSchema
	full, err = (sessionpg.PhonePasswordResetMigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	sessionStep := full[len(full)-1]
	for _, item := range []struct {
		namespace string
		owner     ModuleID
		step      migrations.Migration
		guard     migrationGuard
	}{
		{"identity_phone_reset_kernel", "identity/postgres", kernelStep, migrationGuard{version: 1902, schema: "identity", constraints: []string{"credential_replacements.credential_replacements_operation_check"}, constraintValue: "identity.phone.password-reset-complete"}},
		{"identity_phone_reset_password", "identity/password/postgres", passwordStep, migrationGuard{version: 27, schema: "identity_password", constraints: []string{"replacements.replacements_purpose_check"}, constraintValue: "identity.phone.password-reset-complete"}},
		{"identity_phone_reset_session", "identity/session/postgres", sessionStep, migrationGuard{version: 1, schema: schema, constraints: []string{"password_resets.password_resets_purpose_check"}, constraintValue: "identity.phone.password-reset-complete"}},
	} {
		if slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == item.namespace }) {
			return nil, identity.InvalidInputError{Field: "reference_phone_password_reset_migrations"}
		}
		catalog = append(catalog, migrationHistory{namespace: item.namespace, history: []migrations.Migration{item.step}, owners: map[migrations.Version]ModuleID{item.step.Version(): item.owner}, guards: []migrationGuard{item.guard}})
	}
	return catalog, nil
}
