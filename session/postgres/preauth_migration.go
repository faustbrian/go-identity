package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PreAuthMigrationSource installs canonical session-owned unauthenticated flow
// state after the base session schema. Version is a permanent 1..MaxInt64 slot
// in the sole migration history. Existing session rows/history are unchanged.
// No raw cookie or authenticated proof is stored; terminal custody is retained.
// Load performs no IO; no destructive down migration or cleanup is supplied.
type PreAuthMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns an owned forward-only transaction; nil/canceled context and
// invalid schema/allocation deny before building SQL.
func (s PreAuthMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_preauth_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_preauth", migrations.TransactionModeDefault, strings.ReplaceAll(preAuthSchemaSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const preAuthSchemaSQL = `CREATE TABLE @schema@.preauth_transactions(
 tenant_id @schema@.scope_id NOT NULL,
 flow_id text COLLATE "C" NOT NULL CHECK(flow_id ~ '^[A-Za-z0-9_-]{22}$'),
 record bytea NOT NULL CHECK(octet_length(record) BETWEEN 1 AND 8192),
 issued_at @schema@.instant NOT NULL,
 expires_at @schema@.instant NOT NULL,
 digest_version bigint NOT NULL CHECK(digest_version BETWEEN 1 AND 4294967295),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 issued_version @schema@.version NOT NULL CHECK(issued_version<=18446744073709551613),
 version @schema@.version NOT NULL,
 state text COLLATE "C" NOT NULL CHECK(state IN('issued','reserved','consumed')),
 command_id bytea CHECK(octet_length(command_id)=16),
 fingerprint bytea CHECK(octet_length(fingerprint)=32),
 generation @schema@.version,
 PRIMARY KEY(tenant_id,flow_id),
 UNIQUE(tenant_id,digest_version,digest),
 CHECK(issued_at<expires_at),
 CHECK((state='issued' AND version=issued_version AND command_id IS NULL AND fingerprint IS NULL AND generation IS NULL)
 OR (state IN('reserved','consumed') AND command_id IS NOT NULL AND fingerprint IS NOT NULL AND generation IS NOT NULL
 AND version=issued_version+CASE WHEN state='reserved' THEN 1 ELSE 2 END))
);
CREATE INDEX preauth_expiry_order ON @schema@.preauth_transactions(expires_at,tenant_id,flow_id) WHERE state='issued';
`
