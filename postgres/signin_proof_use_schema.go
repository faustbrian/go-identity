package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// SignInProofUseMigrationSource appends final-authentication proof-use
// tombstones to immutable Base history. Allocate Version explicitly after every
// Base version. The zero value is invalid; no destructive downgrade is supplied.
// This storage is not a session issuer or an authentication authority. It must
// be composed with the protected issuer's current checks and same-transaction
// session, audit, lifecycle and terminal command effects before activation.
type SignInProofUseMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

var _ migrations.Source = SignInProofUseMigrationSource{}

// Load performs no SQL and preserves all previously applied migration bytes.
// Proof identity is unique within its stable trusted authentication namespace,
// across tenants and proof versions. Session deletion must not remove or reset
// these tombstones. Exact replay belongs to the original command journal, never
// another insertion or a reconstructed bearer. Full-width versions and original
// nanosecond expiry are preserved without PostgreSQL timestamp rounding.
func (s SignInProofUseMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "signin_proof_use_migration"}
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, invalid
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalid
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_signin_proof_uses", migrations.TransactionModeDefault, signInProofUseSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const signInProofUseSchemaSQL = `CREATE TABLE identity.signin_proof_uses (
 authority_id text COLLATE "C" NOT NULL CHECK(octet_length(authority_id) BETWEEN 1 AND 256),
 proof_id text COLLATE "C" NOT NULL CHECK(octet_length(proof_id) BETWEEN 22 AND 128 AND proof_id ~ '^[!-~]+$'),
 proof_version identity.version NOT NULL,
 command_id bytea NOT NULL UNIQUE CHECK(octet_length(command_id)=16),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 session_id identity.directory_id NOT NULL,
 expires_at text COLLATE "C" NOT NULL CHECK(expires_at ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[.][0-9]{9}Z$'),
 PRIMARY KEY(authority_id,proof_id)
);`
