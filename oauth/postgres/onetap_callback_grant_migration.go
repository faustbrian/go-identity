package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// OneTapCallbackGrantMigrationSource adds encrypted One Tap callback proof
// custody after MigrationSource in the same native OAuth namespace. Install it
// before enabling the One Tap writer. Legacy RP writers remain unchanged;
// there is no backfill or destructive downgrade. The capability and command
// stores remain the sole owners of redemption and recovery.
type OneTapCallbackGrantMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = OneTapCallbackGrantMigrationSource{}

// Load returns the forward-only schema without I/O. Apply it with the same
// migration runner as the preceding native OAuth schema.
func (s OneTapCallbackGrantMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !rpSchemaName(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_onetap_grant_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(oneTapCallbackGrantSchema, "@schema@", rpQuotedSchema(s.Schema))
	migration, err := migrations.NewMigration(s.Version, "identity_oauth_onetap_callback_grants", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

// Proof custody is independent of the authorization-code RP table: a One Tap
// callback has no PKCE exchange. The new empty table needs no index build on
// existing rows; bound any wait for the FK's referenced command relation.
const oneTapCallbackGrantSchema = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.onetap_callback_grants(
 tenant_id identity.directory_id NOT NULL,
 flow_id bytea NOT NULL CHECK(octet_length(flow_id)=16 AND flow_id<>decode(repeat('00',16),'hex')),
 origin_command_id bytea NOT NULL CHECK(octet_length(origin_command_id)=16),
 origin_operation text COLLATE "C" NOT NULL CHECK(origin_operation='identity.oauth.onetap-start'),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 proof_ciphertext bytea CHECK(octet_length(proof_ciphertext) BETWEEN 1 AND 65536),
 erased_at timestamptz CHECK(isfinite(erased_at)),
 PRIMARY KEY(tenant_id,flow_id),
 UNIQUE(tenant_id,origin_command_id),
 FOREIGN KEY(tenant_id,origin_operation,origin_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK(issued_at>='1970-01-01T00:00:01Z' AND expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 CHECK((erased_at IS NULL AND proof_ciphertext IS NOT NULL)
  OR (erased_at IS NOT NULL AND erased_at>=issued_at AND proof_ciphertext IS NULL))
);
CREATE INDEX onetap_callback_grants_expiry ON @schema@.onetap_callback_grants(expires_at,tenant_id,flow_id)
 WHERE proof_ciphertext IS NOT NULL;
`
