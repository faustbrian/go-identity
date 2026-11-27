package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ProxyTransactionMigrationSource adds encrypted callback-proxy custody after
// MigrationSource in the same OAuth namespace. Apply it before enabling proxy
// writers, using a permanently allocated unused Version in the owning history.
// It changes no existing table or data, requires no backfill and has no
// destructive downgrade. Immutable sources support concurrent Load calls.
//
// Rows project only open custody or a known terminal outcome. The capability
// participant and kernel command journal retain reservation, exchange, replay
// and recovery authority, including unknown outcomes. Native owners authenticate
// original command bindings; this table grants no user or session authority.
type ProxyTransactionMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = ProxyTransactionMigrationSource{}

// Load returns the forward-only schema without I/O. Invalid configuration is
// redacted to a typed input error, and context cancellation is preserved.
// Apply with the existing migrations runner after the base OAuth migration.
func (s ProxyTransactionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !rpSchemaName(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_proxy_transaction_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(proxyTransactionSchema, "@schema@", rpQuotedSchema(s.Schema))
	migration, err := migrations.NewMigration(s.Version, "identity_oauth_proxy_transactions", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

// Only a new empty table and its indexes are created: there is no existing-row
// scan, foreign-key lock or data rewrite. Bound namespace lock waits and keep
// settings transaction-local. The five-minute custody lifetime and 2048-byte
// exact callback bound match oauth/proxy's binding and endpoint validation.
// SQL bounds opaque bytes; the native owner must authenticate the full original
// binding, enforce exact UTC inputs and validate URLs before writing custody.
const proxyTransactionSchema = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.proxy_transactions(
 tenant_id identity.directory_id NOT NULL,
 transaction_id identity.directory_id NOT NULL,
 origin_command_id bytea NOT NULL CHECK(octet_length(origin_command_id)=16),
 callback_command_id bytea NOT NULL CHECK(octet_length(callback_command_id)=16),
 production_deployment text COLLATE "C" NOT NULL CHECK(octet_length(production_deployment) BETWEEN 1 AND 128 AND production_deployment ~ '^[a-z0-9_-]+$'),
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128 AND provider_id ~ '^[a-z0-9_-]+$'),
 configuration_version identity.version NOT NULL,
 production_callback_uri text COLLATE "C" NOT NULL CHECK(octet_length(production_callback_uri) BETWEEN 1 AND 2048),
 state_key_version bigint NOT NULL CHECK(state_key_version BETWEEN 1 AND 4294967295),
 state_lookup_digest bytea NOT NULL CHECK(octet_length(state_lookup_digest)=32 AND state_lookup_digest<>decode(repeat('00',32),'hex')),
 binding_ciphertext bytea NOT NULL CHECK(octet_length(binding_ciphertext) BETWEEN 1 AND 65536),
 state_proof_ciphertext bytea CHECK(octet_length(state_proof_ciphertext) BETWEEN 1 AND 65536),
 pkce_ciphertext bytea CHECK(octet_length(pkce_ciphertext) BETWEEN 1 AND 4096),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 version identity.version NOT NULL,
 outcome smallint,
 handoff_ciphertext bytea CHECK(octet_length(handoff_ciphertext) BETWEEN 1 AND 8192),
 settled_at timestamptz CHECK(isfinite(settled_at)),
 PRIMARY KEY(tenant_id,transaction_id),
 UNIQUE(tenant_id,origin_command_id),
 UNIQUE(tenant_id,callback_command_id),
 UNIQUE(production_deployment,provider_id,configuration_version,state_key_version,state_lookup_digest),
 CHECK(issued_at>='1970-01-01T00:00:01Z' AND expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 CHECK((version=1 AND outcome IS NULL AND handoff_ciphertext IS NULL AND settled_at IS NULL
   AND state_proof_ciphertext IS NOT NULL AND pkce_ciphertext IS NOT NULL)
  OR (version=2 AND outcome IS NOT NULL AND outcome IN(1,2) AND settled_at IS NOT NULL AND settled_at>=issued_at
   AND state_proof_ciphertext IS NULL AND pkce_ciphertext IS NULL
   AND ((outcome=1 AND handoff_ciphertext IS NOT NULL) OR (outcome=2 AND handoff_ciphertext IS NULL))))
);
CREATE INDEX proxy_transactions_expiry ON @schema@.proxy_transactions(expires_at,tenant_id,transaction_id)
 WHERE outcome IS NULL;
`
