package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ProxyPreviewBindingMigrationSource adds encrypted preview-side proxy custody
// after MigrationSource in the same OAuth namespace. Apply it before enabling
// preview writers, using a permanently allocated unused Version in that history.
// It changes no existing table or data, requires no backfill and has no
// destructive downgrade. Immutable sources support concurrent Load calls.
//
// Rows project only open custody or a known terminal result. The capability
// participant and kernel command journal retain reservation, replay and recovery
// authority. Native owners authenticate original command bindings and enforce
// live key and deadline validation; this table grants no identity authority.
type ProxyPreviewBindingMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = ProxyPreviewBindingMigrationSource{}

// Load returns the forward-only schema without I/O. Invalid configuration is
// redacted to a typed input error, and context cancellation is preserved.
// Apply with the existing migrations runner after the base OAuth migration.
func (s ProxyPreviewBindingMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !rpSchemaName(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_proxy_preview_binding_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(proxyPreviewBindingSchema, "@schema@", rpQuotedSchema(s.Schema))
	migration, err := migrations.NewMigration(s.Version, "identity_oauth_proxy_preview_bindings", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

// Only a new empty table and its indexes are created: there is no existing-row
// scan, foreign-key lock or data rewrite. Bound namespace lock waits locally.
// oauth/proxy's original production issuance and five-minute maximum survive
// preview preauthorization clipping; expiry may be shorter, never renewed.
// SQL enforces whole-second instants, not the caller's original UTC location;
// the native owner validates that location and authenticates the opaque binding.
const proxyPreviewBindingSchema = `SET LOCAL lock_timeout = '5s';
CREATE TABLE @schema@.proxy_preview_bindings(
 tenant_id identity.directory_id NOT NULL,
 flow_id identity.directory_id NOT NULL,
 origin_command_id bytea NOT NULL CHECK(octet_length(origin_command_id)=16),
 callback_command_id bytea NOT NULL CHECK(octet_length(callback_command_id)=16),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at) AND issued_at=date_trunc('second',issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at=date_trunc('second',expires_at)),
 binding_ciphertext bytea NOT NULL CHECK(octet_length(binding_ciphertext) BETWEEN 1 AND 65536),
 proof_ciphertext bytea CHECK(octet_length(proof_ciphertext) BETWEEN 1 AND 65536),
 version identity.version NOT NULL,
 settled_at timestamptz CHECK(isfinite(settled_at)),
 PRIMARY KEY(tenant_id,flow_id),
 UNIQUE(tenant_id,origin_command_id),
 UNIQUE(tenant_id,callback_command_id),
 CHECK(origin_command_id<>callback_command_id),
 CHECK(issued_at>='1970-01-01T00:00:01Z' AND expires_at>issued_at AND expires_at<=issued_at+interval '5 minutes'),
 CHECK((version=1 AND proof_ciphertext IS NOT NULL AND settled_at IS NULL)
  OR (version=2 AND proof_ciphertext IS NULL AND settled_at IS NOT NULL AND settled_at>=issued_at))
);
CREATE INDEX proxy_preview_bindings_expiry ON @schema@.proxy_preview_bindings(expires_at,tenant_id,flow_id)
 WHERE version=1;
`
