package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// SSOSAMLIDPSigninMigrationSource extends the installed SP-initiated SAML
// issuance constraint for the exact IdP-initiated SAML purpose. Install both
// versions after both SSOSAMLSigninMigrationSource steps and before selecting
// the IdP-initiated SAML session writer. This opt-in library source does not
// activate any sign-in flow or deploy schema. Keep the expansion on code rollback
// once IdP-initiated SAML issuances exist; no down SQL is provided.
type SSOSAMLIDPSigninMigrationSource struct {
	Schema                     string
	Version, ValidationVersion migrations.Version
}

var _ migrations.Source = SSOSAMLIDPSigninMigrationSource{}

// Load returns a metadata-only expansion and separate validation, with bounded
// lock acquisition in each step. Versions must be positive, strictly ordered and
// within the migration ledger's signed 64-bit range; Schema must be a supported
// session schema identifier. Invalid input, nil context or cancellation returns
// no partial history. The runner owns both transactions. Expansion requires the
// exact validated SP-initiated SAML purpose constraint and retains its complete
// predicate, preserving all previously installed issuance profiles without
// rewriting rows.
func (s SSOSAMLIDPSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_sso_saml_idp_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	schema := pgx.Identifier{s.Schema}.Sanitize()
	const previous = "session_issuances_purpose_sso_saml_v1"
	const next = "session_issuances_purpose_sso_saml_idp_v1"
	// As in the SP-initiated source, replace the template's successor separately
	// from its predecessor so the installed predicate is retained unchanged.
	expansionSQL := strings.NewReplacer(
		"@schema@", schema, "@schema_name@", s.Schema, "@previous@", previous,
		"session_issuances_purpose_sso_oidc_v1", next, "identity.sso.oidc-callback", "identity.sso.saml-idp-init",
		"identity_sso_oidc_signin", "identity_sso_saml_idp_signin", "enterprise OIDC", "enterprise IdP-initiated SAML",
	).Replace(ssoOIDCSigninIssuanceExpansionSQL)
	expansion, err := migrations.NewMigration(s.Version, "identity_session_sso_saml_idp_expand", migrations.TransactionModeDefault, expansionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validationSQL := `SET LOCAL lock_timeout = '5s';
ALTER TABLE ` + schema + `.session_issuances VALIDATE CONSTRAINT ` + next + `;`
	validation, err := migrations.NewMigration(s.ValidationVersion, "identity_session_sso_saml_idp_validate", migrations.TransactionModeDefault, validationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expansion, validation}, nil
}
