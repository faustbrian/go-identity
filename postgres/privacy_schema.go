package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PrivacyExportMigrationSource adds authoritative privacy epoch and destructive
// admission fences to immutable Base history at an explicitly allocated later
// Version. Base must include StatusMigrationSource's authority/status columns.
// Existing users retain IDs, aggregate/security versions and blocked state.
// New creation writers use privacy epoch 1 and idle disposition. Anonymization
// and deletion owners must set their pending disposition under the same user
// lock before initiating cascades; idle is not current authorization.
// This forward-only schema does not create a job, consume proof or run exports.
type PrivacyExportMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

var _ migrations.Source = PrivacyExportMigrationSource{}

// Load returns owned history without IO. Nil/empty Base, non-successor Version
// and nil context fail closed; cancellation is preserved. No destructive down
// is supported because resetting privacy epochs would revive old authority.
func (s PrivacyExportMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "privacy_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "privacy_migration"}
	}
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "privacy_migration"}
		}
	}
	next, err := migrations.NewMigration(s.Version, "identity_privacy_admission", migrations.TransactionModeDefault, privacyAdmissionSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), next), nil
}

const privacyAdmissionSQL = `ALTER TABLE identity.users
 ADD COLUMN privacy_epoch identity.version NOT NULL DEFAULT 1,
 ADD COLUMN privacy_disposition text COLLATE "C" NOT NULL DEFAULT 'idle'
  CHECK(privacy_disposition IN ('idle','anonymization-pending','deletion-pending'));
`
