package reference

import (
	"context"
	"slices"

	migrations "github.com/faustbrian/go-migrations/v3"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func (s StoreSet) directorySyncMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.directorySync == nil {
		return catalog, nil
	}
	catalog, err := organizationCredentialAuthorityMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_enterprise_oidc" }) {
		providers, err := enterpriseProviderMigrationHistory(ctx, false, false)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, providers)
	}
	// Apply the native empty generation table after its provider registry.
	// Keeping a separate history preserves the provider and sign-in prefixes.
	generation := migrationHistory{namespace: "identity_sso_directory_sync", owners: map[migrations.Version]ModuleID{}}
	err = appendEnterpriseMigration(ctx, &generation, "sso/postgres", ssopg.DirectorySyncGenerationMigrationSource{Version: 1},
		migrationGuard{version: 1, schema: "sso_providers", tables: []string{"directory_sync_generations"}})
	if err != nil {
		return nil, err
	}
	return append(catalog, generation), nil
}
