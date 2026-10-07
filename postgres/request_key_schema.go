package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// RequestKeyMigrationSource appends optional immutable request correlation
// storage to Base at an explicit later Version. Base must contain the kernel
// schema; its installed history is unchanged. Mapping is not an execution
// journal and has no mutable state, lease or outcome. Removal/reassignment is
// unsupported: retaining correlation prevents unknown work becoming a new
// command after the replay window. No destructive down migration is provided.
type RequestKeyMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns caller-owned forward-only history without I/O. Nil/empty Base,
// nil context and non-successor Version fail closed; cancellation is preserved.
func (s RequestKeyMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalidRequestKey()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalidRequestKey()
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalidRequestKey()
		}
	}
	next, err := migrations.NewMigration(s.Version, "identity_request_keys", migrations.TransactionModeDefault, requestKeySQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const requestKeySQL = `CREATE TABLE identity.request_key_namespaces (
 namespace identity.directory_id PRIMARY KEY,
 key_identity bytea NOT NULL CHECK(octet_length(key_identity)=32)
);
CREATE TABLE identity.request_key_mappings (
 namespace identity.directory_id NOT NULL REFERENCES identity.request_key_namespaces(namespace),
 tenant_id identity.directory_id NOT NULL,
 actor_id identity.directory_id NOT NULL,
 actor_kind text COLLATE "C" NOT NULL CHECK(actor_kind IN ('user','api-key','service-account')),
 method text COLLATE "C" NOT NULL CHECK(method IN ('POST','PUT','PATCH','DELETE')),
 route_id identity.directory_id NOT NULL,
 key_digest bytea NOT NULL CHECK(octet_length(key_digest)=32),
 command_id bytea NOT NULL UNIQUE CHECK(octet_length(command_id)=16 AND command_id<>decode(repeat('00',16),'hex')),
 fingerprint bytea NOT NULL CHECK(octet_length(fingerprint)=32),
 fingerprint_key_version bigint NOT NULL CHECK(fingerprint_key_version BETWEEN 1 AND 4294967295),
 safe_fields bytea NOT NULL CHECK(octet_length(safe_fields) BETWEEN 1 AND 65536),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(namespace,tenant_id,actor_id,actor_kind,method,route_id,key_digest)
);
CREATE FUNCTION identity.request_key_immutable() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN RAISE EXCEPTION 'immutable request correlation' USING ERRCODE='23514'; END
$fn$;
CREATE TRIGGER request_key_namespace_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON identity.request_key_namespaces FOR EACH STATEMENT EXECUTE FUNCTION identity.request_key_immutable();
CREATE TRIGGER request_key_mapping_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON identity.request_key_mappings FOR EACH STATEMENT EXECUTE FUNCTION identity.request_key_immutable();
`
