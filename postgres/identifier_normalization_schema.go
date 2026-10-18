package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// IdentifierNormalizationMigrationSource appends exact comparison-policy
// identity to directory rows. Empty/zero keeps historical records explicitly
// unbound; no canonical bytes or verification are rewritten. The feature that
// needs normalization binding must select this forward migration before writes.
// Base must include the identifier history; Version follows every Base version.
// It owns no runner, connection or transaction, and supplies no destructive down.
type IdentifierNormalizationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load copies immutable forward history. Missing base, non-successor version,
// nil context or cancellation returns no migrations. SQL installation remains
// the existing migrations Runner's responsibility.
func (s IdentifierNormalizationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "identifier_normalization_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "identifier_normalization_migration"}
	}
	for _, migration := range history {
		if migration.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "identifier_normalization_migration"}
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_identifier_normalization", migrations.TransactionModeDefault, identifierNormalizationSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

// The profile grammar matches go-identifier's NormalizationProfileID. A numeric
// plus scale/range checks rejects fractions rather than rounding a revision.
const identifierNormalizationSQL = `ALTER TABLE identity.identifiers
 ADD COLUMN normalization_profile text COLLATE "C" NOT NULL DEFAULT '',
 ADD COLUMN normalization_version numeric NOT NULL DEFAULT 0,
 ADD CONSTRAINT identity_identifier_normalization_binding CHECK (
  scale(normalization_version)=0 AND (
   (normalization_profile='' AND normalization_version=0) OR
   (octet_length(normalization_profile) BETWEEN 1 AND 128
    AND normalization_profile ~ '^[a-z0-9][a-z0-9._-]*$'
    AND normalization_version BETWEEN 1 AND 4294967295)
  ));
`

var _ migrations.Source = IdentifierNormalizationMigrationSource{}
