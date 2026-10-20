package reference

import (
	"context"

	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Replacement follows the installed removal CHECK predecessors in their
// existing physical namespaces, without selecting removal runtime authority.
// Permanent allocations 1901/26 follow removal's 1900/25. Installing removal
// later therefore cannot overwrite the replacement allowance on populated data.
func (s StoreSet) phoneChangeMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.phoneChange == nil {
		return catalog, nil
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
	steps, err := (kernel.PhoneChangeCascadeMigrationSource{Base: fixedMigrationSource(directory), Version: 1901}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step := steps[len(steps)-1]
	catalog = append(catalog, migrationHistory{namespace: "identity_phone_change_kernel", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{1901: "identity/postgres"}, guards: []migrationGuard{{version: 1901, schema: "identity", constraints: []string{"status_cascades.identity_cascade_scope"}, constraintValue: "identity.phone.update"}}})
	steps, err = (passwordpg.PhoneChangeReauthenticationMigrationSource{Base: fixedMigrationSource(password), Version: 26}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step = steps[len(steps)-1]
	return append(catalog, migrationHistory{namespace: "identity_phone_change_password", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{26: "identity/password/postgres"}, guards: []migrationGuard{{version: 26, schema: "identity_password", constraints: []string{"reauthentication_records.reauthentication_consumption_complete"}, constraintValue: "identity.phone.update"}}}), nil
}
