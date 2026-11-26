package postgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OneTapStartPreparationErasureMigrationSource permits only terminal One Tap
// start to erase its temporary prepared ciphertext. Append after any existing
// preparation-erasure migrations, and before admitting the native writer. It
// does not require or select SSO services, rewrite historical rows, or allow
// erasure of undecided custody.
type OneTapStartPreparationErasureMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends the forward trigger change without database I/O.
func (s OneTapStartPreparationErasureMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	return appendPreparationMigration(ctx, s.Base, s.Version, "identity_oauth_onetap_start_preparation_erasure", oneTapStartPreparationErasureSQL)
}

// Preserve earlier preparation-guard profiles when One Tap is installed in a
// database that already uses them. One Tap shares the closed profile-four
// terminal-only guard, not any enterprise provider or transaction.
const oneTapStartPreparationErasureSQL = ssoEnterprisePreparationErasurePrefix + `OLD.purpose IN('identity.sso.signin-start','identity.sso.saml-start','identity.sso.saml-logout-relay-issue','identity.oauth.onetap-start') AND OLD.preparation_profile=4;
 enterprise_callback boolean := OLD.purpose IN('identity.sso.oidc-callback','identity.sso.oauth-callback','identity.sso.provider-token.refresh','identity.sso.saml-acs','identity.sso.saml-idp-init')` + ssoCallbackPreparationErasureSuffix
