package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// IdentifierMutationMigrationSource appends non-reversible identifier retirement
// history to immutable Base migrations. Version must be allocated after every
// Base version. Existing directory data and explicit-column readers/writers are
// unchanged. Load performs no SQL; use the migrations Runner. Zero is invalid.
// Retirement history must outlive old proofs/imports; destructive down is absent.
type IdentifierMutationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns independently owned forward-only history. Cancellation is
// preserved; nil/empty Base and non-successor versions fail closed. This schema
// does not authorize mutations or establish cleanup/retention policy.
func (s IdentifierMutationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "identifier_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "identifier_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "identifier_migration"}
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_identifier_retirements", migrations.TransactionModeDefault, identifierRetirementSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const identifierRetirementSQL = `CREATE TABLE identity.identifier_retirements (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 identifier_id identity.directory_id NOT NULL,
 kind text COLLATE "C" NOT NULL CHECK(kind IN ('email','phone','username','provider-subject')),
 record_version identity.version NOT NULL,
 verification_version identity.version NOT NULL,
 removed boolean NOT NULL,
 command_id text COLLATE "C" NOT NULL CHECK(command_id ~ '^[A-Za-z0-9_-]{22}$'),
 key_version bigint NOT NULL CHECK(key_version BETWEEN 1 AND 4294967295),
 value_digest bytea NOT NULL CHECK(octet_length(value_digest)=32),
 retired_at timestamptz NOT NULL CHECK(isfinite(retired_at) AND retired_at >= '0001-01-01 00:00:00+00'::timestamptz),
 reuse_until timestamptz NOT NULL CHECK(isfinite(reuse_until) AND reuse_until>=retired_at AND reuse_until < '10000-01-01 00:00:00+00'::timestamptz),
 PRIMARY KEY(tenant_id,identifier_id,record_version),
 UNIQUE(tenant_id,command_id),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id)
);
CREATE INDEX identity_identifier_reuse ON identity.identifier_retirements(tenant_id,kind,key_version,value_digest,reuse_until);
`

var _ migrations.Source = IdentifierMutationMigrationSource{}
