package reference

import (
	"context"
	"slices"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Removal extends the installed physical owners, not enrollment's OTP history.
// Existing namespaces/checksums stay unchanged when removal is selected later.
func (s StoreSet) phoneRemovalMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.phoneRemoval == nil {
		return catalog, nil
	}
	// The selected protected owner enforces durable lockouts. Reuse the native
	// namespace allocated by MFA/username, without selecting either workflow.
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_risk_lockouts" }) {
		schema := s.state.config.Schema
		base := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: schema, Version: 1}, Version: 2}, Version: 3}, Version: 4}
		steps, err := (riskpg.LockoutMigrationSource{Base: base, Version: 5}).Load(ctx)
		if err != nil {
			return nil, err
		}
		step := steps[len(steps)-1]
		catalog = append(catalog, migrationHistory{namespace: "identity_risk_lockouts", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{5: "identity/risk/postgres"}, guards: []migrationGuard{{version: 5, schema: schema, tables: []string{"counter_lockouts"}}}})
	}
	catalog, err := emailRemovalMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	var directory, password []migrations.Migration
	for _, h := range catalog {
		for _, step := range h.history {
			switch h.owners[step.Version()] {
			case "identity/postgres":
				directory = append(directory, step)
			case "identity/password/postgres":
				password = append(password, step)
			}
		}
	}
	steps, err := (kernel.PhoneRemovalCascadeMigrationSource{Base: fixedMigrationSource(directory), Version: 1900}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step := steps[len(steps)-1]
	catalog = append(catalog, migrationHistory{namespace: "identity_phone_removal_kernel", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{1900: "identity/postgres"}, guards: []migrationGuard{{version: 1900, schema: "identity", constraints: []string{"status_cascades.identity_cascade_scope"}, constraintValue: "identity.phone.remove"}}})
	steps, err = (passwordpg.PhoneRemovalReauthenticationMigrationSource{Base: fixedMigrationSource(password), Version: 25}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step = steps[len(steps)-1]
	return append(catalog, migrationHistory{namespace: "identity_phone_removal_password", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{25: "identity/password/postgres"}, guards: []migrationGuard{{version: 25, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.phone.remove"}}}), nil
}
