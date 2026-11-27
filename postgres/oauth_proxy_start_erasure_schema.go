package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OAuthProxyStartPreparationErasureMigrationSource permits the native proxy
// start's terminal profile-four preparation to discard its duplicate encrypted
// output. Append after existing preparation-erasure history, including proxy
// forwarding, before enabling the optional start writer. Installation neither
// rewrites pending or historical rows nor grants initiation authority.
type OAuthProxyStartPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends the forward trigger change without database I/O.
func (s OAuthProxyStartPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_oauth_proxy_start_preparation_erasure", oauthProxyStartPreparationErasureSQL)
}

// Keep every earlier erasure profile while extending the existing terminal-only
// start rule to temporary proxy PKCE/state custody. Unknown starts retain their
// original recovery output (identity-oauth-proxy.md, state and PKCE binding).
const oauthProxyStartPreparationErasureSQL = ssoEnterprisePreparationErasurePrefix + `OLD.purpose IN('identity.sso.signin-start','identity.sso.saml-start','identity.sso.saml-logout-relay-issue','identity.oauth.onetap-start','identity.oauth.proxy-start') AND OLD.preparation_profile=4;
 enterprise_callback boolean := OLD.purpose IN('identity.sso.oidc-callback','identity.sso.oauth-callback','identity.sso.provider-token.refresh','identity.sso.saml-acs','identity.sso.saml-idp-init','identity.oauth.onetap-callback','identity.oauth.proxy-forward')` + ssoCallbackPreparationErasureSuffix
