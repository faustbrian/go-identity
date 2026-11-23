package reference

import (
	"context"
	"slices"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	organizationpg "github.com/faustbrian/go-organization/postgres"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func (s StoreSet) enterpriseOIDCMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	f := s.state.features
	if f == nil || f.enterpriseSessionSchema() == "" {
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

	roleSync := f.enterpriseOIDC != nil && f.enterpriseOIDC.roleSync
	if roleSync {
		roles := migrationHistory{namespace: "identity_organization_provider_roles", owners: map[migrations.Version]ModuleID{}}
		if err := appendEnterpriseMigration(ctx, &roles, "organization/postgres", organizationpg.ProviderRoleGrantMigrationSource{Version: 1}, migrationGuard{
			version: 1, schema: "organization", tables: []string{"provider_role_sources", "provider_role_grants"},
		}); err != nil {
			return nil, err
		}
		if err := appendEnterpriseMigration(ctx, &roles, "organization/postgres", organizationpg.ProviderRoleSourceProjectionMigrationSource{Version: 2}, migrationGuard{
			version: 2, schema: "organization", functions: []string{"project_provider_role_source", "invalidate_provider_role_source_policy"},
		}); err != nil {
			return nil, err
		}
		catalog = append(catalog, roles)
	}

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
	if roleSync {
		// Keep the baseline provider prefix: the optional trigger must run only
		// after the organization's role history and the installed provider schema.
		if err := appendEnterpriseMigration(ctx, &providers, "sso/postgres", ssopg.ProviderRoleSourceMigrationSource{Version: 7}, migrationGuard{
			version: 7, schema: "sso_providers", functions: []string{"project_provider_role_source_change"},
		}); err != nil {
			return nil, err
		}
	}
	catalog = append(catalog, providers)

	schema := f.enterpriseSessionSchema()
	sessions := migrationHistory{namespace: "identity_enterprise_oidc_session", owners: map[migrations.Version]ModuleID{}}
	source := sessionpg.SSOOIDCSigninMigrationSource{Schema: schema, Version: 1, ValidationVersion: 2, PreviousConstraint: sessionIssuancePredecessor(catalog, schema)}
	if err := appendEnterpriseMigration(ctx, &sessions, "identity/session/postgres", source, migrationGuard{version: 1, schema: schema,
		constraints: []string{"session_issuances.session_issuances_purpose_sso_oidc_v1"}}); err != nil {
		return nil, err
	}
	catalog = append(catalog, sessions)
	if f.enterpriseOIDC == nil {
		return catalog, nil
	}
	if f.enterpriseOIDC.logout != nil {
		catalog, err = enterpriseOIDCLogoutMigrationCatalog(ctx, catalog, schema)
		if err != nil {
			return nil, err
		}
	}
	switch {
	case f.enterpriseOIDC.jit:
		return enterpriseOIDCJITMigrationCatalog(ctx, catalog)
	case f.enterpriseOIDC.memberLink:
		return enterpriseOIDCSubjectMigrationCatalog(ctx, catalog)
	default:
		return catalog, nil
	}
}

func enterpriseOIDCLogoutMigrationCatalog(ctx context.Context, catalog []migrationHistory, sessionSchema string) ([]migrationHistory, error) {
	// Keep logout independent of the installed provider prefix and optional
	// role-sync version 7, including when roles are selected later.
	provider := migrationHistory{namespace: "identity_enterprise_oidc_logout_provider", owners: map[migrations.Version]ModuleID{}}
	if err := appendEnterpriseMigration(ctx, &provider, "sso/postgres", ssopg.ProviderLogoutMigrationSource{Version: 1}, migrationGuard{
		version: 1, schema: "sso_providers", tables: []string{"logout_transactions"},
	}); err != nil {
		return nil, err
	}
	revocations := migrationHistory{namespace: "identity_enterprise_oidc_logout_session", owners: map[migrations.Version]ModuleID{}}
	source := sessionpg.SSOOIDCLogoutMigrationSource{Schema: sessionSchema, Version: 1, ValidationVersion: 2, PreviousConstraint: "session_revocations_purpose_check"}
	// Expansion owns creation of this constraint. An interrupted validation
	// must leave a recognized native prefix, not an unmanaged schema collision.
	if err := appendEnterpriseMigration(ctx, &revocations, "identity/session/postgres", source, migrationGuard{
		version: 1, schema: sessionSchema, constraints: []string{"session_revocations.session_revocations_purpose_sso_oidc_v1"},
	}); err != nil {
		return nil, err
	}
	return append(catalog, provider, revocations), nil
}

func (f *featureState) enterpriseSessionSchema() string {
	if f.enterpriseOIDC != nil {
		return f.enterpriseOIDC.sessionSchema
	}
	if f.enterpriseOAuth2 != nil {
		return f.enterpriseOAuth2.sessionSchema
	}
	return ""
}

func (s StoreSet) enterpriseOAuth2MigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	f := s.state.features
	if f == nil || f.enterpriseOAuth2 == nil {
		return catalog, nil
	}
	// The existing provider history owns optional OIDC role migration 7.
	// A separate suffix allows selecting it after installing OAuth2.
	protocol := migrationHistory{namespace: "identity_enterprise_oauth2", owners: map[migrations.Version]ModuleID{}}
	for _, step := range []struct {
		source migrations.Source
		guard  migrationGuard
	}{
		{ssopg.ProviderProtocolMigrationSource{Version: 1, ValidationVersion: 2}, migrationGuard{version: 1,
			columns: []string{"providers.protocol"}, constraints: []string{"providers.sso_providers_protocol_check"}}},
		{ssopg.LoginTransactionProtocolMigrationSource{Version: 3, ValidationVersion: 4}, migrationGuard{version: 3,
			constraints: []string{"login_transactions.login_transactions_protocol_check"}, constraintValue: "oauth2"}},
		{ssopg.ProviderLoginTokenVaultProtocolMigrationSource{Version: 5, ValidationVersion: 6}, migrationGuard{version: 5,
			constraints: []string{"provider_login_token_sets.provider_login_token_sets_origin_operation_check"}, constraintValue: enterpriseOAuth2CallbackAction}},
	} {
		step.guard.schema = "sso_providers"
		if err := appendEnterpriseMigration(ctx, &protocol, "sso/postgres", step.source, step.guard); err != nil {
			return nil, err
		}
	}
	schema := f.enterpriseOAuth2.sessionSchema
	sessions := migrationHistory{namespace: "identity_enterprise_oauth2_session", owners: map[migrations.Version]ModuleID{}}
	source := sessionpg.SSOOAuth2SigninMigrationSource{Schema: schema, Version: 1, ValidationVersion: 2}
	if err := appendEnterpriseMigration(ctx, &sessions, "identity/session/postgres", source, migrationGuard{version: 1, schema: schema,
		constraints: []string{"session_issuances.session_issuances_purpose_sso_oauth2_v1"}}); err != nil {
		return nil, err
	}
	return append(catalog, protocol, sessions), nil
}

func enterpriseOIDCJITMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	catalog, err := identifierMutationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	base := fixedMigrationSource(catalog[0].history)
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == "identity_username_kernel" }) {
		// Reuse the directory normalization allocation even when username and
		// phone are off so selecting them later cannot reapply these columns.
		const version = 1800
		steps, err := (kernel.IdentifierNormalizationMigrationSource{Base: base, Version: version}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_username_kernel", history: steps[len(steps)-1:],
			owners: map[migrations.Version]ModuleID{version: "identity/postgres"},
			guards: []migrationGuard{{version: version, schema: "identity", columns: []string{"identifiers.normalization_profile", "identifiers.normalization_version"}}}})
	}
	catalog, err = enterpriseOIDCSubjectMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}

	// Physical factor authority keeps its existing namespace and legacy signup
	// checks. These independent steps affect only the alternate JIT provenance.
	factors, err := (mfapg.SSOOIDCJITFactorMigrationSource{Base: mfapg.MigrationSource{Version: 1}, Version: 2, ValidationVersion: 3, IndexVersion: 4}).LoadOffline(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_enterprise_oidc_jit_factors", history: factors[1:],
		owners: map[migrations.Version]ModuleID{2: "identity/mfa/postgres", 3: "identity/mfa/postgres", 4: "identity/mfa/postgres"},
		guards: []migrationGuard{{version: 2, schema: "identity_mfa", columns: []string{"factor_authorities.sso_oidc_initialized_purpose"},
			constraints: []string{"factor_authorities.factor_authorities_initialization_provenance_v1", "factor_authorities.factor_authorities_sso_oidc_command_fkey"}},
			{version: 4, schema: "identity_mfa", tables: []string{"factor_authorities_sso_oidc_command_unique"}}}}), nil
}

func enterpriseOIDCSubjectMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	const version = 1850
	// Retain the JIT allocation for both opt-in profiles. The Reference command
	// commits each migration with its receipt, so it uses the offline variant.
	base := fixedMigrationSource(catalog[0].history)
	steps, err := (kernel.SSOOIDCSubjectAvailabilityMigrationSource{Base: base, Version: version}).LoadOffline(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_enterprise_oidc_jit_directory", history: steps[len(steps)-1:],
		owners: map[migrations.Version]ModuleID{version: "identity/postgres"},
		guards: []migrationGuard{{version: version, schema: "identity", tables: []string{"identity_accounts_retired_subject"}}}}), nil
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
