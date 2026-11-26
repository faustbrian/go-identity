package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OneTapCallbackPreparationErasureMigrationSource permits the exact terminal
// One Tap callback to erase its encrypted preparation with its definitive
// original receipt. Append after existing preparation-erasure migrations.
// Pending/unknown custody remains immutable; retained history and earlier
// profiles are unchanged. Installing this guard does not enable any callback.
type OneTapCallbackPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends the forward trigger change without database I/O.
func (s OneTapCallbackPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_oauth_onetap_callback_preparation_erasure", oneTapCallbackPreparationErasureSQL)
}

const oneTapCallbackPreparationErasureSQL = ssoEnterprisePreparationErasurePrefix + `OLD.purpose IN('identity.sso.signin-start','identity.sso.saml-start','identity.sso.saml-logout-relay-issue','identity.oauth.onetap-start') AND OLD.preparation_profile=4;
 enterprise_callback boolean := OLD.purpose IN('identity.sso.oidc-callback','identity.sso.oauth-callback','identity.sso.provider-token.refresh','identity.sso.saml-acs','identity.sso.saml-idp-init','identity.oauth.onetap-callback')` + ssoCallbackPreparationErasureSuffix
