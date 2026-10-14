package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// RequestKeyPreparationMigrationSource appends optional immutable code-free
// input custody to existing request-key mappings. Base must include the original
// RequestKeyMigrationSource; Version must follow all installed history. Existing
// checksums and rows are unchanged, and legacy mappings are never backfilled.
// The existing mapping trigger prohibits modification/removal of either new
// field. This adds no journal, lease, outcome or execution authority. No
// destructive downgrade is supported; install before enabling the new API.
type RequestKeyPreparationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns owned forward history without I/O; nil, cancelled, empty or
// non-successor input fails without fabricating a migration.
func (s RequestKeyPreparationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	next, err := migrations.NewMigration(s.Version, "identity_request_key_preparation", migrations.TransactionModeDefault, requestKeyPreparationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const requestKeyPreparationSQL = `ALTER TABLE identity.request_key_mappings
 ADD COLUMN request_preparation_identity bytea,
 ADD COLUMN request_preparation_ciphertext bytea,
 ADD CONSTRAINT identity_request_preparation_shape CHECK (
  num_nonnulls(request_preparation_identity,request_preparation_ciphertext)=0
  OR (request_preparation_identity IS NOT NULL AND octet_length(request_preparation_identity)=32
   AND request_preparation_ciphertext IS NOT NULL
   AND octet_length(request_preparation_ciphertext) BETWEEN 1 AND 1048576));
`
