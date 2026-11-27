package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OAuthProxyForwardPreparationErasureMigrationSource permits only the native
// proxy callback's terminal profile-four preparation to discard its duplicate
// encrypted output. Append after existing preparation-erasure history before
// enabling the proxy writer. Pending and historical custody is not rewritten;
// installation grants no callback or preview authority.
type OAuthProxyForwardPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends the forward trigger change without database I/O.
func (s OAuthProxyForwardPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_oauth_proxy_forward_preparation_erasure", oauthProxyForwardPreparationErasureSQL)
}

// Preserve every earlier selected erasure profile while extending only the
// existing terminal profile-four rule to the proxy callback. Pending custody
// remains immutable, as required by identity-oauth-proxy.md's exchange recovery.
const oauthProxyForwardPreparationErasureSQL = ssoEnterprisePreparationErasurePrefix + `OLD.purpose IN('identity.sso.signin-start','identity.sso.saml-start','identity.sso.saml-logout-relay-issue','identity.oauth.onetap-start') AND OLD.preparation_profile=4;
 enterprise_callback boolean := OLD.purpose IN('identity.sso.oidc-callback','identity.sso.oauth-callback','identity.sso.provider-token.refresh','identity.sso.saml-acs','identity.sso.saml-idp-init','identity.oauth.onetap-callback','identity.oauth.proxy-forward')` + ssoCallbackPreparationErasureSuffix
