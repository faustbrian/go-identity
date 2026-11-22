package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// SSOOAuth2SigninMigrationSource extends the installed enterprise OIDC issuance
// constraint without rewriting history. Install after both OIDC issuance steps
// and before selecting the OAuth writer; neither protocol needs to be enabled.
type SSOOAuth2SigninMigrationSource struct {
	Schema                     string
	Version, ValidationVersion migrations.Version
}

// Load returns a metadata-only expansion and separate validation, with bounded
// lock acquisition in each step. The migration runner owns both transactions.
func (s SSOOAuth2SigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_sso_oauth2_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	schema := pgx.Identifier{s.Schema}.Sanitize()
	// Carry the original validated predicate, including all its optional older
	// issuance profiles. These replacements are fixed SQL tokens, not input.
	const previous = "session_issuances_purpose_sso_oidc_v1"
	const next = "session_issuances_purpose_sso_oauth2_v1"
	expansionSQL := strings.NewReplacer(
		"@schema@", schema, "@schema_name@", s.Schema, "@previous@", previous,
		previous, next, "identity.sso.oidc-callback", "identity.sso.oauth-callback",
		"identity_sso_oidc_signin", "identity_sso_oauth2_signin", "enterprise OIDC", "enterprise OAuth2",
	).Replace(ssoOIDCSigninIssuanceExpansionSQL)
	expansion, err := migrations.NewMigration(s.Version, "identity_session_sso_oauth2_expand", migrations.TransactionModeDefault, expansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validationSQL := `SET LOCAL lock_timeout = '5s';
ALTER TABLE ` + schema + `.session_issuances VALIDATE CONSTRAINT ` + next + `;`
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_session_sso_oauth2_validate", migrations.TransactionModeDefault, validationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expansion, validation}, nil
}
