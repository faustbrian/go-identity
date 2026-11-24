package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// SSOSAMLIDPLogoutMigrationSource adds bounded command evidence for an
// IdP-initiated SAML logout target set to an installed dedicated session schema.
// Install this separate additive migration through the existing Runner before
// opting into the target-set writer; loading it enables no flow or deployment.
// Version is a permanently allocated 1..MaxInt64 slot in the same history.
// Retain the table on code rollback: evidence has no session FK and survives
// session pruning. No destructive down migration is provided.
type SSOSAMLIDPLogoutMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = SSOSAMLIDPLogoutMigrationSource{}

// Load returns one forward-only migration without IO and is safe for concurrent
// callers. Invalid schema/version or nil context returns no history; context
// cancellation is preserved. The Runner owns the transaction. The new table is
// empty, so its constraints require no populated-table scan; the short local
// lock timeout bounds acquisition of the referenced command table's FK lock.
func (s SSOSAMLIDPLogoutMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_sso_saml_idp_logout_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(ssoSAMLIDPLogoutSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	migration, err := migrations.NewMigration(s.Version, "identity_session_sso_saml_idp_logout", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

const ssoSAMLIDPLogoutSchemaSQL = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.saml_idp_logout_revocations(
 tenant_id @schema@.scope_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.sso.saml-slo'),
 user_id @schema@.scope_id NOT NULL,
 binding_digest bytea NOT NULL CHECK(octet_length(binding_digest)=32),
 intent_digest bytea NOT NULL CHECK(octet_length(intent_digest)=32),
 target_count integer NOT NULL CHECK(target_count BETWEEN 1 AND 128),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(command_id,tenant_id,purpose) REFERENCES identity.commands(command_id,tenant_id,purpose)
);
`
