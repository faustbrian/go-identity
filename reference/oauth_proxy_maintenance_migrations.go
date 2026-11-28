package reference

import (
	"context"

	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// OAuthProxyMaintenanceSchema selects a separately planned migration phase.
type OAuthProxyMaintenanceSchema uint8

const (
	// OAuthProxyMaintenanceExpand installs empty stores and nullable projections.
	OAuthProxyMaintenanceExpand OAuthProxyMaintenanceSchema = iota + 1
	// OAuthProxyMaintenanceActivate adds the insert fence after expansion and
	// deployment of all fenced writers for the selected custody database.
	OAuthProxyMaintenanceActivate
)

func (p OAuthProxyMaintenanceSchema) valid() bool {
	return p == OAuthProxyMaintenanceExpand || p == OAuthProxyMaintenanceActivate
}

func proxyMaintenanceMigrationSuffix(ctx context.Context, schema string, kind kernel.OAuthProxyRetirementKind, phase OAuthProxyMaintenanceSchema) ([]migrations.Migration, []migrationGuard, error) {
	if ctx == nil || !phase.valid() {
		return nil, nil, invalidOAuthProxyMaintenance()
	}
	var history []migrations.Migration
	var guards []migrationGuard
	add := func(source migrations.Source, guard migrationGuard) error {
		loaded, err := source.Load(ctx)
		if err != nil {
			return err
		}
		history = append(history, loaded...)
		guard.schema = schema
		guards = append(guards, guard)
		return nil
	}
	var fenceVersion, drainVersion, activateVersion migrations.Version
	var custody, fence, role string
	switch kind {
	case kernel.OAuthProxyRetireProduction:
		if err := add(oauthpg.ProviderDisableCascadeMigrationSource{Schema: schema, Version: 6},
			migrationGuard{version: 6, tables: []string{"provider_disable_cascades"}}); err != nil {
			return nil, nil, err
		}
		fenceVersion, drainVersion, activateVersion = 7, 8, 10
		custody, fence, role = "proxy_transactions", "proxy_production_write_fences", "production"
	case kernel.OAuthProxyRetirePreview:
		fenceVersion, drainVersion, activateVersion = 6, 7, 8
		custody, fence, role = "proxy_preview_bindings", "proxy_preview_write_fences", "preview"
	default:
		return nil, nil, invalidOAuthProxyMaintenance()
	}
	if err := add(oauthpg.ProxyCustodyWriteFenceMigrationSource{Schema: schema, Version: fenceVersion, Kind: kind},
		migrationGuard{version: fenceVersion, tables: []string{fence}, columns: []string{custody + ".fence_provider_id", custody + ".fence_provider_epoch"}}); err != nil {
		return nil, nil, err
	}
	if err := add(oauthpg.ProxyRetirementDrainMigrationSource{Schema: schema, Version: drainVersion},
		migrationGuard{version: drainVersion, tables: []string{"proxy_retirement_drains"}}); err != nil {
		return nil, nil, err
	}
	if kind == kernel.OAuthProxyRetireProduction {
		if err := add(oauthpg.ProxyDisablePairMigrationSource{Schema: schema, Version: 9},
			migrationGuard{version: 9, tables: []string{"provider_disable_proxy_pairs"}}); err != nil {
			return nil, nil, err
		}
	}
	if phase == OAuthProxyMaintenanceActivate {
		if err := add(oauthpg.ProxyCustodyWriteFenceActivationSource{Schema: schema, Version: activateVersion, Kind: kind},
			migrationGuard{version: activateVersion, functions: []string{"enforce_proxy_" + role + "_write_fence"}}); err != nil {
			return nil, nil, err
		}
	}
	return history, guards, nil
}
