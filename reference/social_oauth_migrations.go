package reference

import (
	"context"
	"strings"

	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Optional social linking appends native-owner histories after its real
// password/session prerequisites; every previously installed prefix is intact.
func (s StoreSet) socialOAuthMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	f := s.state.features
	if f == nil || f.socialOAuth == nil && f.enterpriseSessionSchema() == "" && (f.oneTap == nil || f.oneTap.complete == nil) {
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
	var accountHistory migrations.Source = kernel.AccountLinkPreparationErasureValidationMigrationSource{Base: linkErasure, Version: 2404}
	enterpriseSchema := f.enterpriseSessionSchema()
	if enterpriseSchema != "" || f.socialOAuth != nil && f.socialOAuth.unlink != nil {
		expand := kernel.AccountUnlinkPreparationMigrationSource{Base: accountHistory, Version: 2405}
		accountHistory = kernel.AccountUnlinkPreparationValidationMigrationSource{Base: expand, Version: 2406}
	}
	if enterpriseSchema != "" {
		// This is the existing account/preparation history, not a second copy of
		// the account tables. The enterprise erasure suffix retains social rules.
		refresh := kernel.OAuthProviderRefreshErasureMigrationSource{Base: accountHistory, Version: 2407}
		start := kernel.SSOOIDCPreparationErasureMigrationSource{Base: refresh, Version: 2408}
		accountHistory = kernel.SSOOIDCCallbackPreparationErasureMigrationSource{Base: start, Version: 2409}
	}
	if f.enterpriseOAuth2 != nil || f.enterpriseSAML != nil {
		accountHistory = kernel.SSOOAuth2CallbackPreparationErasureMigrationSource{Base: accountHistory, Version: 2410}
	}
	if f.enterpriseSAML != nil {
		refresh := kernel.SSOEnterpriseGrantRefreshPreparationErasureMigrationSource{Base: accountHistory, Version: 2411}
		callback := kernel.SSOSAMLCallbackPreparationErasureMigrationSource{Base: refresh, Version: 2412}
		accountHistory = kernel.SSOSAMLStartPreparationErasureMigrationSource{Base: callback, Version: 2413}
		start := f.enterpriseSAML.logoutStart
		relayState := start != nil && start.relayState
		if f.enterpriseSAML.idpStorage || relayState {
			// Relay erasure replaces the same trigger and preserves the IdP
			// rule. Keep its predecessor even without the IdP sign-in route.
			accountHistory = kernel.SSOSAMLIDPConfirmationPreparationErasureMigrationSource{Base: accountHistory, Version: 2414}
		}
		if relayState {
			accountHistory = kernel.SSOSAMLLogoutRelayIssuePreparationErasureMigrationSource{Base: accountHistory, Version: 2415}
		}
	}
	full, err := accountHistory.Load(ctx)
	if err != nil {
		return nil, err
	}
	steps := full[len(catalog[0].history):]
	h := migrationHistory{namespace: "identity_social_kernel", history: steps, owners: map[migrations.Version]ModuleID{}, guards: []migrationGuard{{version: 2400, schema: "identity", tables: []string{"accounts", "account_credentials"}}}}
	for _, m := range steps {
		h.owners[m.Version()] = "identity/postgres"
	}
	catalog = append(catalog, h)
	if f.socialOAuth == nil {
		if enterpriseSchema == "" {
			return catalog, nil // One Tap uses the same account history, not auth-code session issuance.
		}
		return appendOAuthSigninSessionMigration(ctx, catalog, enterpriseSchema)
	}
	schema := f.socialOAuth.schema
	rp, err := (oauthpg.MigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	vault, err := (oauthpg.TokenVaultMigrationSource{Schema: schema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	oauthHistory := migrationHistory{namespace: "identity_social_oauth", history: append(rp, vault...), owners: map[migrations.Version]ModuleID{1: "identity/oauth/postgres", 2: "identity/oauth/postgres"}, guards: []migrationGuard{{version: 1, schema: schema}, {version: 2, schema: schema, tables: []string{"token_sets"}}}}
	if f.oauthProxyPreview != nil {
		const previewVersion = 3
		bindings, err := (oauthpg.ProxyPreviewBindingMigrationSource{Schema: schema, Version: previewVersion}).Load(ctx)
		if err != nil {
			return nil, err
		}
		oauthHistory.history = append(oauthHistory.history, bindings...)
		oauthHistory.owners[previewVersion] = "identity/oauth/postgres"
		oauthHistory.guards = append(oauthHistory.guards, migrationGuard{version: previewVersion, schema: schema, tables: []string{"proxy_preview_bindings"}})
	}
	catalog = append(catalog, oauthHistory)
	if f.socialOAuth.unlink != nil {
		var predecessors []migrations.Migration
		for _, history := range catalog {
			for _, step := range history.history {
				if history.owners[step.Version()] == "identity/password/postgres" {
					predecessors = append(predecessors, step)
				}
			}
		}
		steps, err := (passwordpg.AccountUnlinkReauthenticationMigrationSource{Base: fixedMigrationSource(predecessors), Version: 43}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{
			namespace: "identity_social_unlink_password", history: steps[len(predecessors):],
			owners: map[migrations.Version]ModuleID{43: "identity/password/postgres", 44: "identity/password/postgres", 45: "identity/password/postgres"},
			guards: []migrationGuard{{version: 43, schema: "identity_password", columns: []string{"reauthentication_records.unlink_consumed_command_id"}}},
		})
	}
	if signin := f.socialOAuth.signin; signin != nil {
		return appendOAuthSigninSessionMigration(ctx, catalog, signin.sessionSchema)
	}
	if enterpriseSchema != "" {
		return appendOAuthSigninSessionMigration(ctx, catalog, enterpriseSchema)
	}
	return catalog, nil
}

func appendOAuthSigninSessionMigration(ctx context.Context, catalog []migrationHistory, schema string) ([]migrationHistory, error) {
	// Enterprise always extends this physical prefix, even with no social
	// owner. Otherwise later social opt-in changes the installed enterprise
	// checksum and targets a constraint that enterprise already replaced.
	source := sessionpg.OAuthSigninMigrationSource{Schema: schema, Version: 1, ValidationVersion: 2, PreviousConstraint: sessionIssuancePredecessor(catalog, schema)}
	steps, err := source.Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_social_signin_session", history: steps,
		owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"},
		guards: []migrationGuard{{version: 1, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_oauth_v1"}}}}), nil
}

func sessionIssuancePredecessor(catalog []migrationHistory, schema string) string {
	previous := "session_issuances_purpose_check"
	for _, history := range catalog {
		for _, guard := range history.guards {
			if guard.schema != schema {
				continue
			}
			for _, constraint := range guard.constraints {
				if strings.HasPrefix(constraint, "session_issuances.session_issuances_purpose_") {
					previous = strings.TrimPrefix(constraint, "session_issuances.")
				}
			}
		}
	}
	return previous
}
