package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MigrationSource installs forward-only native RP transaction custody after
// the identity kernel. Schema must be a dedicated lowercase SQL namespace;
// Version is a permanently allocated unused positive history version. Existing
// schemas fail rather than being adopted. Installation selects no provider,
// route, authentication or replay authority and provides no destructive down.
// Load performs no IO and immutable sources support concurrent calls.
type MigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = MigrationSource{}

// Load returns independently owned SQL or a redacted typed configuration error.
// Cancellation is preserved. Apply using the existing migrations runner in the
// composition's single history; this source owns no runner or transaction.
func (s MigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !rpSchemaName(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(rpTransactionSchema, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	migration, err := migrations.NewMigration(s.Version, "identity_oauth_rp_transactions", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{migration}, nil
}

func rpSchemaName(value string) bool {
	if len(value) == 0 || len(value) > 63 || value == "identity" || value == "public" || value == "information_schema" || strings.HasPrefix(value, "pg_") {
		return false
	}
	for index := range len(value) {
		b := value[index]
		if b >= 'a' && b <= 'z' || index > 0 && (b >= '0' && b <= '9' || b == '_') {
			continue
		}
		return false
	}
	return true
}

// This is encrypted RP data, not a replay/lease/exchange journal. Canonical
// capability reservation and the kernel command journal retain those owners.
// Lookup uses only a named-key state commitment. The separately encrypted state
// proof is validated before reservation; PKCE is released only after reservation.
// binding_ciphertext must not duplicate raw PKCE or the canonical state bearer.
// Nullable subject/session fields retain their original kind without a fake user.
// Secret erasure preserves non-bearer lookup/binding metadata for reconciliation.
const rpTransactionSchema = `CREATE SCHEMA @schema@;
CREATE TABLE @schema@.transactions(
 tenant_id identity.directory_id NOT NULL,
 transaction_id identity.directory_id NOT NULL,
 origin_command_id bytea NOT NULL CHECK(octet_length(origin_command_id)=16),
 operation text COLLATE "C" NOT NULL CHECK(operation IN('identity.account.link-start','identity.oauth.signin-start')),
 user_id identity.directory_id,
 preauth_id identity.directory_id,
 session_id identity.directory_id,
 session_version identity.version,
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128 AND provider_id ~ '^[a-z0-9_-]+$'),
 configuration_version identity.version NOT NULL,
 issuer text COLLATE "C" NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 1024),
 client_id text COLLATE "C" NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 1024),
 redirect_uri text COLLATE "C" NOT NULL CHECK(octet_length(redirect_uri) BETWEEN 1 AND 1024),
 response_mode text COLLATE "C" NOT NULL CHECK(response_mode='query'),
 state_key_version bigint NOT NULL CHECK(state_key_version BETWEEN 1 AND 4294967295),
 state_digest bytea NOT NULL CHECK(octet_length(state_digest)=32 AND state_digest<>decode(repeat('00',32),'hex')),
 pkce_key_version bigint NOT NULL CHECK(pkce_key_version BETWEEN 1 AND 4294967295),
 pkce_commitment bytea NOT NULL CHECK(octet_length(pkce_commitment)=32 AND pkce_commitment<>decode(repeat('00',32),'hex')),
 pkce_ciphertext bytea CHECK(octet_length(pkce_ciphertext) BETWEEN 1 AND 4096),
 state_proof_ciphertext bytea CHECK(octet_length(state_proof_ciphertext) BETWEEN 1 AND 65536),
 binding_ciphertext bytea NOT NULL CHECK(octet_length(binding_ciphertext) BETWEEN 1 AND 65536),
 issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at)),
 version identity.version NOT NULL,
 secrets_erased_at timestamptz CHECK(isfinite(secrets_erased_at)),
 PRIMARY KEY(tenant_id,transaction_id),
 UNIQUE(tenant_id,origin_command_id),
 UNIQUE(tenant_id,state_key_version,state_digest),
 CHECK(issued_at>='1970-01-01T00:00:01Z' AND expires_at>issued_at AND expires_at<=issued_at+interval '10 minutes'),
 CHECK((operation='identity.account.link-start' AND user_id IS NOT NULL AND preauth_id IS NULL AND session_id IS NOT NULL AND session_version IS NOT NULL)
  OR (operation='identity.oauth.signin-start' AND user_id IS NULL AND preauth_id IS NOT NULL AND session_id IS NULL AND session_version IS NULL)),
 CHECK((secrets_erased_at IS NULL AND pkce_ciphertext IS NOT NULL AND state_proof_ciphertext IS NOT NULL)
  OR (secrets_erased_at IS NOT NULL AND secrets_erased_at>=issued_at AND pkce_ciphertext IS NULL AND state_proof_ciphertext IS NULL)),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 FOREIGN KEY(tenant_id,operation,origin_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
CREATE INDEX rp_transactions_expiry ON @schema@.transactions(expires_at,tenant_id,transaction_id);
`
