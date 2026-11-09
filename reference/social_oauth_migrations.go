package reference

import (
	"context"

	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Optional social linking appends native-owner histories after its real
// password/session prerequisites; every previously installed prefix is intact.
func (s StoreSet) socialOAuthMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.socialOAuth == nil {
		return catalog, nil
	}
	var err error
	catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	aliases, err := (riskpg.CounterKeyVersionMigrationSource{Schema: s.state.config.Schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_social_counter_keys", history: aliases, owners: map[migrations.Version]ModuleID{1: "identity/risk/postgres"}, guards: []migrationGuard{{version: 1, schema: s.state.config.Schema, columns: []string{"counter_charges.key_versions"}, functions: []string{"guard_counter_key_versions"}}}})
	base := fixedMigrationSource(catalog[0].history)
	accounts := kernel.AccountMigrationSource{Base: base, Version: 2400}
	preparation := kernel.AccountLinkPreparationMigrationSource{Base: accounts, Version: 2401}
	startErasure := kernel.OAuthRPPreparationErasureMigrationSource{Base: preparation, Version: 2402}
	linkErasure := kernel.AccountLinkPreparationErasureMigrationSource{Base: startErasure, Version: 2403}
	full, err := (kernel.AccountLinkPreparationErasureValidationMigrationSource{Base: linkErasure, Version: 2404}).Load(ctx)
	if err != nil {
		return nil, err
	}
	steps := full[len(catalog[0].history):]
	h := migrationHistory{namespace: "identity_social_kernel", history: steps, owners: map[migrations.Version]ModuleID{}, guards: []migrationGuard{{version: 2400, schema: "identity", tables: []string{"accounts", "account_credentials"}}}}
	for _, m := range steps {
		h.owners[m.Version()] = "identity/postgres"
	}
	catalog = append(catalog, h)
	schema := s.state.features.socialOAuth.schema
	rp, err := (oauthpg.MigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	vault, err := (oauthpg.TokenVaultMigrationSource{Schema: schema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_social_oauth", history: append(rp, vault...), owners: map[migrations.Version]ModuleID{1: "identity/oauth/postgres", 2: "identity/oauth/postgres"}, guards: []migrationGuard{{version: 1, schema: schema}, {version: 2, schema: schema, tables: []string{"token_sets"}}}}), nil
}
