package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// SSOSAMLSigninMigrationSource extends the installed enterprise OAuth2 issuance
// constraint for the exact SP-initiated SAML ACS purpose. Install both versions
// after both SSOOAuth2SigninMigrationSource steps and before selecting the SAML
// session writer. This opt-in library source does not activate any sign-in flow
// or deploy schema. Keep the expansion on code rollback once SAML issuances
// exist; no down SQL is provided.
type SSOSAMLSigninMigrationSource struct {
	Schema                     string
	Version, ValidationVersion migrations.Version
}

var _ migrations.Source = SSOSAMLSigninMigrationSource{}

// Load returns a metadata-only expansion and separate validation, with bounded
// lock acquisition in each step. Versions must be positive, strictly ordered and
// within the migration ledger's signed 64-bit range; Schema must be a supported
// session schema identifier. Invalid input, nil context or cancellation returns
// no partial history. The runner owns both transactions. Expansion requires the
// exact validated OAuth2 purpose constraint and retains its complete predicate,
// preserving all previously installed issuance profiles without rewriting rows.
func (s SSOSAMLSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_sso_saml_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	schema := pgx.Identifier{s.Schema}.Sanitize()
	const previous = "session_issuances_purpose_sso_oauth2_v1"
	const next = "session_issuances_purpose_sso_saml_v1"
	// The shared template emits the OIDC successor name independently of its
	// predecessor token. Replace both explicitly while retaining its catalog
	// predicate preservation and validated, single-purpose-column check.
	expansionSQL := strings.NewReplacer(
		"@schema@", schema, "@schema_name@", s.Schema, "@previous@", previous,
		"session_issuances_purpose_sso_oidc_v1", next, "identity.sso.oidc-callback", "identity.sso.saml-acs",
		"identity_sso_oidc_signin", "identity_sso_saml_signin", "enterprise OIDC", "enterprise SAML",
	).Replace(ssoOIDCSigninIssuanceExpansionSQL)
	expansion, err := migrations.NewMigration(s.Version, "identity_session_sso_saml_expand", migrations.TransactionModeDefault, expansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validationSQL := `SET LOCAL lock_timeout = '5s';
ALTER TABLE ` + schema + `.session_issuances VALIDATE CONSTRAINT ` + next + `;`
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_session_sso_saml_validate", migrations.TransactionModeDefault, validationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expansion, validation}, nil
}
