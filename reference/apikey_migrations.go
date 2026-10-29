package reference

import (
	"context"
	"slices"

	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func (s StoreSet) apiKeyMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.apiKey == nil {
		return catalog, nil
	}
	catalog, err := counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_risk_lockouts" }) {
		schema := s.state.config.Schema
		base := riskpg.CounterMigrationSource{Base: riskpg.ReservationMigrationSource{Base: riskpg.IssuanceIDMigrationSource{Base: riskpg.MigrationSource{Schema: schema, Version: 1}, Version: 2}, Version: 3}, Version: 4}
		steps, err := (riskpg.LockoutMigrationSource{Base: base, Version: 5}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_risk_lockouts", history: steps[len(steps)-1:], owners: map[migrations.Version]ModuleID{5: "identity/risk/postgres"}, guards: []migrationGuard{{version: 5, schema: schema, tables: []string{"counter_lockouts"}}}})
	}
	var source migrations.Source = apikeypg.MigrationSource{Version: 1}
	owners := map[migrations.Version]ModuleID{1: "identity/apikey/postgres"}
	guards := []migrationGuard{{version: 1, schema: "identity_api_keys", tables: []string{"configurations", "keys", "command_effects"}}}
	if s.state.features.apiKey.legacy {
		source = apikeypg.LegacyMigrationSource{Base: source, Version: 2}
		owners[2] = "identity/apikey/postgres"
		guards = append(guards, migrationGuard{version: 2, schema: "identity_api_keys", tables: []string{"legacy_imports"}})
	}
	steps, err := source.Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_api_keys", history: steps, owners: owners, guards: guards}), nil
}
