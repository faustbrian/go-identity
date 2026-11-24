package reference

import (
	"context"
	"slices"

	kernel "github.com/faustbrian/go-identity/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	ssopg "github.com/faustbrian/go-sso/postgres"
)

func (s StoreSet) enterpriseSAMLMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	f := s.state.features
	if f == nil || f.enterpriseSAML == nil {
		return catalog, nil
	}
	// SAML extends the shared provider and OAuth2 session custody already
	// installed above. These are storage predecessors; they enable no routes.
	providers := migrationHistory{namespace: "identity_enterprise_saml", owners: map[migrations.Version]ModuleID{}}
	for _, step := range []struct {
		source migrations.Source
		guard  migrationGuard
	}{
		{ssopg.ProviderSAMLProtocolMigrationSource{Version: 1, ValidationVersion: 2}, migrationGuard{version: 1,
			constraints: []string{"providers.sso_providers_protocol_check"}, constraintValue: "saml"}},
		{ssopg.LoginTransactionSAMLProtocolMigrationSource{Version: 3, ValidationVersion: 4}, migrationGuard{version: 3,
			constraints: []string{"login_transactions.login_transactions_saml_lifetime_check"}}},
		{ssopg.SAMLReplayMigrationSource{Version: 5}, migrationGuard{version: 5, tables: []string{"saml_replay_members"}}},
	} {
		step.guard.schema = "sso_providers"
		if err := appendEnterpriseMigration(ctx, &providers, "sso/postgres", step.source, step.guard); err != nil {
			return nil, err
		}
	}
	schema := f.enterpriseSAML.sessionSchema
	sessions := migrationHistory{namespace: "identity_enterprise_saml_session", owners: map[migrations.Version]ModuleID{}}
	source := sessionpg.SSOSAMLSigninMigrationSource{Schema: schema, Version: 1, ValidationVersion: 2}
	if err := appendEnterpriseMigration(ctx, &sessions, "identity/session/postgres", source, migrationGuard{version: 1, schema: schema,
		constraints: []string{"session_issuances.session_issuances_purpose_sso_saml_v1"}}); err != nil {
		return nil, err
	}
	if f.enterpriseSAML.idpStorage {
		if err := appendEnterpriseSAMLIDPMigrations(ctx, &providers, &sessions, schema); err != nil {
			return nil, err
		}
	}

	base := catalog[0].history
	const aliasesVersion migrations.Version = 2451
	aliases := kernel.CanonicalRequestMigrationSource{Base: fixedMigrationSource(base), Version: aliasesVersion}
	full, err := (kernel.CanonicalSAMLStartRequestMigrationSource{Base: aliases, Version: aliasesVersion + 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	requests := migrationHistory{namespace: "identity_enterprise_saml_requests", history: full[len(base):], owners: map[migrations.Version]ModuleID{}, guards: []migrationGuard{
		{version: aliasesVersion, schema: "identity", tables: []string{"request_key_aliases"}},
		{version: aliasesVersion + 1, schema: "identity", constraints: []string{"request_key_mappings.request_key_mappings_saml_start_method",
			"request_key_aliases.request_key_aliases_saml_start_method"}},
	}}
	for _, migration := range requests.history {
		requests.owners[migration.Version()] = "identity/postgres"
	}
	catalog = append(catalog, providers, sessions, requests)
	if f.enterpriseSAML.logout != nil {
		catalog, err = appendEnterpriseSAMLLogoutMigrations(ctx, catalog, schema)
		if err != nil {
			return nil, err
		}
	}
	if start := f.enterpriseSAML.logoutStart; start != nil {
		return appendEnterpriseSAMLLogoutStartMigrations(ctx, catalog, schema, start.remote != nil)
	}
	return catalog, nil
}

const enterpriseSAMLLogoutStartConstraint = "session_revocations_purpose_sso_saml_v1"

func appendEnterpriseSAMLLogoutStartMigrations(ctx context.Context, catalog []migrationHistory, sessionSchema string, remote bool) ([]migrationHistory, error) {
	// Retain one predecessor checksum regardless of which protocol is enabled
	// first. Selecting the shared session history alone installs no OIDC route
	// or provider-specific table.
	if !slices.ContainsFunc(catalog, func(h migrationHistory) bool { return h.namespace == enterpriseOIDCLogoutSessionHistory }) {
		var err error
		catalog, err = appendEnterpriseOIDCLogoutSessionMigrations(ctx, catalog, sessionSchema)
		if err != nil {
			return nil, err
		}
	}
	sessions := migrationHistory{namespace: "identity_enterprise_saml_logout_start_session", owners: map[migrations.Version]ModuleID{}}
	if err := appendEnterpriseMigration(ctx, &sessions, "identity/session/postgres", sessionpg.SSOSAMLLogoutStartMigrationSource{
		Schema: sessionSchema, Version: 1, ValidationVersion: 2, PreviousConstraint: enterpriseOIDCLogoutSessionConstraint,
	}, migrationGuard{version: 1, schema: sessionSchema, constraints: []string{"session_revocations." + enterpriseSAMLLogoutStartConstraint}}); err != nil {
		return nil, err
	}
	catalog = append(catalog, sessions)
	if !remote {
		return catalog, nil
	}
	providers := migrationHistory{namespace: "identity_enterprise_saml_logout_redirect", owners: map[migrations.Version]ModuleID{}}
	if err := appendEnterpriseMigration(ctx, &providers, "sso/postgres", ssopg.SAMLLogoutRequestMigrationSource{Version: 1},
		migrationGuard{version: 1, schema: "sso_providers", tables: []string{"saml_logout_requests"}}); err != nil {
		return nil, err
	}
	if err := appendEnterpriseMigration(ctx, &providers, "sso/postgres", ssopg.SAMLLogoutResponseMigrationSource{Version: 2},
		migrationGuard{version: 2, schema: "sso_providers", tables: []string{"saml_logout_responses"}}); err != nil {
		return nil, err
	}
	return append(catalog, providers), nil
}

func appendEnterpriseSAMLLogoutMigrations(ctx context.Context, catalog []migrationHistory, sessionSchema string) ([]migrationHistory, error) {
	// Separate histories keep logout installable before or after the optional
	// unsolicited sign-in migrations without changing either installed prefix.
	providers := migrationHistory{namespace: "identity_enterprise_saml_logout_provider", owners: map[migrations.Version]ModuleID{}}
	if err := appendEnterpriseMigration(ctx, &providers, "sso/postgres", ssopg.SAMLLogoutSubjectMigrationSource{Version: 1}, migrationGuard{
		version: 1, schema: "sso_providers", tables: []string{"saml_logout_subjects"},
	}); err != nil {
		return nil, err
	}
	sessions := migrationHistory{namespace: "identity_enterprise_saml_logout_session", owners: map[migrations.Version]ModuleID{}}
	if err := appendEnterpriseMigration(ctx, &sessions, "identity/session/postgres", sessionpg.SSOSAMLIDPLogoutMigrationSource{
		Schema: sessionSchema, Version: 1,
	}, migrationGuard{version: 1, schema: sessionSchema, tables: []string{"saml_idp_logout_revocations"}}); err != nil {
		return nil, err
	}
	return append(catalog, providers, sessions), nil
}

func appendEnterpriseSAMLIDPMigrations(ctx context.Context, providers, sessions *migrationHistory, sessionSchema string) error {
	if err := appendEnterpriseMigration(ctx, providers, "sso/postgres", ssopg.SAMLIDPReplayMigrationSource{Version: 6, ValidationVersion: 7}, migrationGuard{
		version: 6, schema: "sso_providers", constraints: []string{"saml_replay_members.saml_replay_members_callback_purpose_check"}, constraintValue: "identity.sso.saml-idp-init",
	}); err != nil {
		return err
	}
	if err := appendEnterpriseMigration(ctx, providers, "sso/postgres", ssopg.SAMLIDPConfirmationMigrationSource{Version: 8}, migrationGuard{
		version: 8, schema: "sso_providers", tables: []string{"saml_idp_confirmations"},
	}); err != nil {
		return err
	}
	return appendEnterpriseMigration(ctx, sessions, "identity/session/postgres", sessionpg.SSOSAMLIDPSigninMigrationSource{
		Schema: sessionSchema, Version: 3, ValidationVersion: 4,
	}, migrationGuard{version: 3, schema: sessionSchema, constraints: []string{samlIDPSessionIssuanceConstraint}})
}
