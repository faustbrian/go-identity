package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// OIDCEndSessionMigrationSource adds only the exact RP-logout purpose to the
// existing single-session revocation owner. It creates no protocol revocation
// journal and preserves every predecessor row, SQL checksum and uniqueness
// fence. Install after RevokeOneMigrationSource, allocating Version permanently.
// No workflow is enabled and no destructive downgrade is supplied.
type OIDCEndSessionMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns the forward-only suffix without IO. The existing migration
// runner fails on absent/mismatched predecessor constraints; invalid scope,
// version, nil context and cancellation fail before installation.
func (s OIDCEndSessionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_oidc_end_session_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(oidcEndSessionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_oidc_end_session", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{m}, nil
}

const oidcEndSessionSQL = `ALTER TABLE @schema@.session_revocations
 DROP CONSTRAINT session_revocations_purpose_check,
 ADD CONSTRAINT session_revocations_purpose_oidc_v1 CHECK(purpose IN('identity.session.revoke-one','identity.oauth-server.end-session'));
`
