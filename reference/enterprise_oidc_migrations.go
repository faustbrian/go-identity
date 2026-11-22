package reference

import (
	"context"
	"slices"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func (s StoreSet) enterpriseOIDCMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	f := s.state.features
	if f == nil || f.enterpriseOIDC == nil {
		return catalog, nil
	}
	catalog, err := organizationCredentialAuthorityMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	catalog, err = emailOTPFactorMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_capability" }) {
		source, err := migrations.NewFSSource(ownedMigrationFiles{capabilitypg.Migrations()}, ".")
		if err != nil {
			return nil, err
		}
		capability := migrationHistory{namespace: "identity_capability", owners: map[migrations.Version]ModuleID{}}
		if err := appendEnterpriseMigration(ctx, &capability, "capability/postgres/identity", source, migrationGuard{version: 1, schema: "public", tables: []string{"capability_identity_one_use"}}); err != nil {
			return nil, err
		}
		catalog = append(catalog, capability)
	}
	domains := migrationHistory{namespace: "identity_organization_domains", owners: map[migrations.Version]ModuleID{}}
	if err := appendEnterpriseMigration(ctx, &domains, "organization/postgres", organizationpg.DomainClaimMigrationSource{Version: 1}, migrationGuard{version: 1, schema: "organization", tables: []string{"domain_claims"}}); err != nil {
		return nil, err
	}
	if err := appendEnterpriseMigration(ctx, &domains, "organization/postgres", organizationpg.DomainEvidenceMigrationSource{Version: 2}, migrationGuard{version: 2, schema: "organization", tables: []string{"domain_evidence"}}); err != nil {
		return nil, err
	}
	catalog = append(catalog, domains)

	providers := migrationHistory{namespace: "identity_enterprise_oidc", owners: map[migrations.Version]ModuleID{}}
	for _, step := range []struct {
		source migrations.Source
		guard  migrationGuard
	}{
		{ssopg.ProviderMigrationSource{Version: 1}, migrationGuard{version: 1, tables: []string{"providers"}}},
		{ssopg.ProviderUpdateMigrationSource{Version: 2}, migrationGuard{version: 2, columns: []string{"providers.metadata_version"}}},
		{ssopg.ProviderCredentialsMigrationSource{Version: 3}, migrationGuard{version: 3, tables: []string{"credentials", "credential_effects"}}},
		{ssopg.ProviderEnableMigrationSource{Version: 4}, migrationGuard{version: 4, tables: []string{"enable_receipts"}}},
		{ssopg.LoginTransactionMigrationSource{Version: 5}, migrationGuard{version: 5, tables: []string{"login_transactions", "provider_login_dispositions"}}},
		{ssopg.ProviderLoginTokenVaultMigrationSource{Version: 6}, migrationGuard{version: 6, tables: []string{"provider_login_token_sets"}}},
	} {
		step.guard.schema = "sso_providers"
		if err := appendEnterpriseMigration(ctx, &providers, "sso/postgres", step.source, step.guard); err != nil {
			return nil, err
		}
	}
	catalog = append(catalog, providers)

	schema := f.enterpriseOIDC.sessionSchema
	sessions := migrationHistory{namespace: "identity_enterprise_oidc_session", owners: map[migrations.Version]ModuleID{}}
	source := sessionpg.SSOOIDCSigninMigrationSource{Schema: schema, Version: 1, ValidationVersion: 2, PreviousConstraint: sessionIssuancePredecessor(catalog, schema)}
	if err := appendEnterpriseMigration(ctx, &sessions, "identity/session/postgres", source, migrationGuard{version: 1, schema: schema,
		constraints: []string{"session_issuances.session_issuances_purpose_sso_oidc_v1"}}); err != nil {
		return nil, err
	}
	return append(catalog, sessions), nil
}

func appendEnterpriseMigration(ctx context.Context, history *migrationHistory, owner ModuleID, source migrations.Source, guard migrationGuard) error {
	steps, err := source.Load(ctx)
	if err != nil {
		return err
	}
	for _, step := range steps {
		history.owners[step.Version()] = owner
	}
	history.history = append(history.history, steps...)
	history.guards = append(history.guards, guard)
	return nil
}
