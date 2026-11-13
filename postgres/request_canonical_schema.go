package postgres

import (
	"context"
	"math"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// CanonicalRequestMigrationSource appends optional immutable retry-key aliases
// to existing request-key/preparation history. Apply before enabling canonical
// DELETE. Existing mappings, ciphertext, claims and journals are not rewritten
// or backfilled. Aliases point only to existing mapping primary keys; they have
// no state, lease, outcome, independent command allocation or cleanup policy.
// Rollback disables new code, never drops original custody. No down migration
// is provided. Lock acquisition is bounded to five seconds.
type CanonicalRequestMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns owned forward-only history without I/O. Version must follow all
// Base entries; nil/empty history and cancellation fail closed.
func (s CanonicalRequestMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	next, err := migrations.NewMigration(s.Version, "identity_canonical_request_aliases", migrations.TransactionModeDefault, canonicalRequestSQL, "")
	if err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const canonicalRequestSQL = `SET LOCAL lock_timeout='5s';
CREATE TABLE identity.request_key_aliases (
 namespace identity.directory_id NOT NULL,
 tenant_id identity.directory_id NOT NULL,
 actor_id identity.directory_id NOT NULL,
 actor_kind text COLLATE "C" NOT NULL CHECK(actor_kind IN ('user','api-key','service-account')),
 method text COLLATE "C" NOT NULL CHECK(method='DELETE'),
 route_id identity.directory_id NOT NULL,
 alias_digest bytea NOT NULL CHECK(octet_length(alias_digest)=32),
 canonical_digest bytea NOT NULL CHECK(octet_length(canonical_digest)=32),
 PRIMARY KEY(namespace,tenant_id,actor_id,actor_kind,method,route_id,alias_digest),
 FOREIGN KEY(namespace,tenant_id,actor_id,actor_kind,method,route_id,canonical_digest)
 REFERENCES identity.request_key_mappings(namespace,tenant_id,actor_id,actor_kind,method,route_id,key_digest)
);
CREATE TRIGGER request_key_alias_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON identity.request_key_aliases FOR EACH STATEMENT EXECUTE FUNCTION identity.request_key_immutable();
`
