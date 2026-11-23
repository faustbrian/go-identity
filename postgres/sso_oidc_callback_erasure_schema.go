package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// SSOOIDCCallbackPreparationErasureMigrationSource lets only the native
// enterprise callback profile discard its temporary encrypted output in the
// same terminal write that records the definitive receipt. Pending and
// historical rows are not rewritten. Install after the enterprise start
// erasure migration and before enabling the native callback writer.
type SSOOIDCCallbackPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends the forward trigger-function update without database I/O.
func (s SSOOIDCCallbackPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_sso_oidc_callback_preparation_erasure", ssoOIDCCallbackPreparationErasureSQL)
}

// SSOOAuth2CallbackPreparationErasureMigrationSource extends terminal-only
// custody erasure to the separate OAuth 2.0 callback. Append after
// SSOOIDCCallbackPreparationErasureMigrationSource before enabling the native
// OAuth writer. It does not rewrite pending or historical rows.
type SSOOAuth2CallbackPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends only the forward trigger-function update; it performs no I/O.
func (s SSOOAuth2CallbackPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_sso_oauth2_callback_preparation_erasure", ssoOAuth2CallbackPreparationErasureSQL)
}

// SSOEnterpriseGrantRefreshPreparationErasureMigrationSource allows the selected
// refresh command to erase its temporary encrypted successor with the terminal
// result. Append after SSOOAuth2CallbackPreparationErasureMigrationSource before
// enabling the refresh writer. Pending and historical rows remain unchanged.
type SSOEnterpriseGrantRefreshPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends a forward trigger-function update; it performs no I/O.
func (s SSOEnterpriseGrantRefreshPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_sso_enterprise_grant_refresh_preparation_erasure", ssoEnterpriseGrantRefreshPreparationErasureSQL)
}

// SSOSAMLCallbackPreparationErasureMigrationSource lets the exact native ACS
// discard temporary encrypted preparation only with a definitive result.
// Append after SSOEnterpriseGrantRefreshPreparationErasureMigrationSource and
// before admitting SAML callbacks. Existing pending and historical rows stay
// unchanged; rollback keeps the widened trigger and all retained output.
type SSOSAMLCallbackPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends the forward-only trigger change without I/O.
func (s SSOSAMLCallbackPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_sso_saml_callback_preparation_erasure", ssoSAMLCallbackPreparationErasureSQL)
}

// SSOSAMLStartPreparationErasureMigrationSource extends the existing terminal
// profile-four guard to the distinct SP-initiated SAML start. Append after
// SSOSAMLCallbackPreparationErasureMigrationSource before admitting SAML
// starts. No existing row or predecessor migration is rewritten.
type SSOSAMLStartPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends only the forward trigger change without performing I/O.
func (s SSOSAMLStartPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_sso_saml_start_preparation_erasure", ssoSAMLStartPreparationErasureSQL)
}

// SSOSAMLIDPConfirmationPreparationErasureMigrationSource expands profile-four
// terminal erasure to unsolicited SAML confirmation. Append after
// SSOSAMLStartPreparationErasureMigrationSource and before enabling its native
// contributor. No pending or historical custody is removed by installation.
type SSOSAMLIDPConfirmationPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends only the forward trigger change; it performs no database I/O.
func (s SSOSAMLIDPConfirmationPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_sso_saml_idp_confirmation_preparation_erasure", ssoSAMLIDPConfirmationPreparationErasureSQL)
}

const ssoOIDCCallbackPreparationErasureSQL = ssoCallbackPreparationErasurePrefix + `OLD.purpose='identity.sso.oidc-callback'` + ssoCallbackPreparationErasureSuffix
const ssoOAuth2CallbackPreparationErasureSQL = ssoCallbackPreparationErasurePrefix + `OLD.purpose IN('identity.sso.oidc-callback','identity.sso.oauth-callback')` + ssoCallbackPreparationErasureSuffix
const ssoEnterpriseGrantRefreshPreparationErasureSQL = ssoCallbackPreparationErasurePrefix + `OLD.purpose IN('identity.sso.oidc-callback','identity.sso.oauth-callback','identity.sso.provider-token.refresh')` + ssoCallbackPreparationErasureSuffix
const ssoSAMLCallbackPreparationErasureSQL = ssoCallbackPreparationErasurePrefix + `OLD.purpose IN('identity.sso.oidc-callback','identity.sso.oauth-callback','identity.sso.provider-token.refresh','identity.sso.saml-acs')` + ssoCallbackPreparationErasureSuffix

const ssoSAMLStartPreparationErasureSQL = ssoEnterprisePreparationErasurePrefix + `OLD.purpose IN('identity.sso.signin-start','identity.sso.saml-start') AND OLD.preparation_profile=4;
 enterprise_callback boolean := OLD.purpose IN('identity.sso.oidc-callback','identity.sso.oauth-callback','identity.sso.provider-token.refresh','identity.sso.saml-acs')` + ssoCallbackPreparationErasureSuffix

const ssoSAMLIDPConfirmationPreparationErasureSQL = ssoEnterprisePreparationErasurePrefix + `OLD.purpose IN('identity.sso.signin-start','identity.sso.saml-start') AND OLD.preparation_profile=4;
 enterprise_callback boolean := OLD.purpose IN('identity.sso.oidc-callback','identity.sso.oauth-callback','identity.sso.provider-token.refresh','identity.sso.saml-acs','identity.sso.saml-idp-init')` + ssoCallbackPreparationErasureSuffix

const ssoCallbackPreparationErasurePrefix = ssoEnterprisePreparationErasurePrefix + `OLD.purpose='identity.sso.signin-start' AND OLD.preparation_profile=4;
 enterprise_callback boolean := `

const ssoEnterprisePreparationErasurePrefix = `SET LOCAL lock_timeout = '5s';
CREATE OR REPLACE FUNCTION identity.guard_command_preparation() RETURNS trigger
 LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE
 rp_start boolean := OLD.purpose IN('identity.account.link-start','identity.oauth.signin-start');
 account_preparation boolean := (OLD.purpose='identity.account.link-token' AND OLD.preparation_profile=5)
  OR (OLD.purpose='identity.account.unlink' AND OLD.preparation_profile=6);
 provider_refresh boolean := OLD.purpose='identity.account.refresh-token' AND OLD.preparation_profile IN(2,4);
 enterprise_start boolean := `
const ssoCallbackPreparationErasureSuffix = ` AND OLD.preparation_profile=4;
 erasing boolean := ((rp_start AND OLD.preparation_profile IN(1,2,3,4)) OR account_preparation OR provider_refresh OR enterprise_start OR enterprise_callback)
  AND OLD.state='pending' AND NEW.state IN('committed','aborted')
  AND NEW.preparation_ciphertext IS NULL AND NEW.preparation_ciphertext_generation IS NULL;
BEGIN
 IF (OLD.preparation_profile IS NOT NULL AND NEW.preparation_profile IS DISTINCT FROM OLD.preparation_profile)
 OR (OLD.preparation_started_generation IS NOT NULL AND NEW.preparation_started_generation IS DISTINCT FROM OLD.preparation_started_generation)
 OR (OLD.preparation_ciphertext IS NOT NULL AND (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
  OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation) AND NOT erasing)
 OR ((rp_start OR account_preparation OR provider_refresh OR enterprise_start OR enterprise_callback) AND OLD.state IN('committed','aborted') AND
  (NEW.preparation_ciphertext IS DISTINCT FROM OLD.preparation_ciphertext
   OR NEW.preparation_ciphertext_generation IS DISTINCT FROM OLD.preparation_ciphertext_generation)) THEN
  RAISE EXCEPTION USING ERRCODE='23514', MESSAGE='identity command preparation immutable';
 END IF;
 RETURN NEW;
END;
$$;
`
