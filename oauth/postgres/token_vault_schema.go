package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// TokenVaultMigrationSource appends token custody to an already installed RP
// namespace and identity account schema. Version is an unused positive history
// version allocated after those prerequisites. Load performs no I/O. Installation
// does not create links, token credentials, provider policy or refresh authority.
// Apply with the composition's existing migrations runner; no down is provided.
type TokenVaultMigrationSource struct {
	Schema  string
	Version migrations.Version
}

var _ migrations.Source = TokenVaultMigrationSource{}

// Load returns a caller-owned forward migration. Invalid namespace/version and
// cancellation return no partial history; existing token tables fail installation
// rather than being silently adopted. No transaction or runner is owned here.
func (s TokenVaultMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !rpSchemaName(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "oauth_token_vault_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(rpTokenVaultSchema, "@schema@", rpQuotedSchema(s.Schema))
	m, err := migrations.NewMigration(s.Version, "identity_oauth_token_vault", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

// Seconds and nanoseconds preserve actual TokenSet timestamps exactly; using
// timestamptz alone would silently round the original response to microseconds.
// Account/link versions remain references to identity-owned state. This table
// owns only its token version and social_connection version, initially one.
const rpTokenVaultSchema = `CREATE TABLE @schema@.token_sets(
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 account_id identity.directory_id NOT NULL,
 provider_id text COLLATE "C" NOT NULL CHECK(octet_length(provider_id) BETWEEN 1 AND 128 AND provider_id ~ '^[a-z0-9_-]+$'),
 issuer text COLLATE "C" NOT NULL CHECK(octet_length(issuer) BETWEEN 1 AND 1024),
 client_id text COLLATE "C" NOT NULL CHECK(octet_length(client_id) BETWEEN 1 AND 1024),
 configuration_version identity.version NOT NULL,
 account_version identity.version NOT NULL,
 social_link_version identity.version NOT NULL,
 version identity.version NOT NULL,
 social_connection_version identity.version NOT NULL,
 requested_scopes text[] NOT NULL CHECK(cardinality(requested_scopes) BETWEEN 1 AND 32 AND array_position(requested_scopes,NULL) IS NULL AND octet_length(array_to_string(requested_scopes,' ')) BETWEEN 1 AND 4127),
 granted_scopes text[] NOT NULL CHECK(cardinality(granted_scopes) BETWEEN 1 AND 32 AND array_position(granted_scopes,NULL) IS NULL AND octet_length(array_to_string(granted_scopes,' ')) BETWEEN 1 AND 4127),
 scope_reported boolean NOT NULL,
 received_at_seconds bigint NOT NULL CHECK(received_at_seconds BETWEEN 1 AND 253402300799),
 received_at_nanoseconds integer NOT NULL CHECK(received_at_nanoseconds BETWEEN 0 AND 999999999),
 access_expires_at_seconds bigint NOT NULL CHECK(access_expires_at_seconds BETWEEN 1 AND 253402300799),
 access_expires_at_nanoseconds integer NOT NULL CHECK(access_expires_at_nanoseconds BETWEEN 0 AND 999999999),
 token_ciphertext bytea NOT NULL CHECK(octet_length(token_ciphertext) BETWEEN 1 AND 65536),
 origin_operation text COLLATE "C" NOT NULL CHECK(origin_operation='identity.account.link-token'),
 origin_command_id bytea NOT NULL CHECK(octet_length(origin_command_id)=16),
 PRIMARY KEY(tenant_id,account_id),
 FOREIGN KEY(tenant_id,user_id,account_id) REFERENCES identity.accounts(tenant_id,user_id,account_id),
 FOREIGN KEY(tenant_id,origin_operation,origin_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK(access_expires_at_seconds>received_at_seconds AND access_expires_at_seconds<=received_at_seconds+31536000 AND access_expires_at_nanoseconds=received_at_nanoseconds),
 CHECK(granted_scopes<@requested_scopes AND (scope_reported OR granted_scopes=requested_scopes))
);
CREATE INDEX token_sets_expiry ON @schema@.token_sets(access_expires_at_seconds,access_expires_at_nanoseconds,tenant_id,account_id);
`
