package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// AnonymousUpgradeDisposalMigrationSource appends the explicit upgrade purpose
// to existing kernel disposal evidence. All populated predecessor SQL and unique
// guest tombstones remain unchanged. Select this forward-only suffix before the
// upgrade workflow; the original deletion profile needs no new migration.
type AnonymousUpgradeDisposalMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load validates the selected predecessor and increasing suffix without IO.
func (s AnonymousUpgradeDisposalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "anonymous_upgrade_disposal_migration"}
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
	found := false
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalid
		}
		found = found || m.Name() == "identity_anonymous_disposals"
	}
	if !found {
		return nil, invalid
	}
	m, err := migrations.NewMigration(s.Version, "identity_anonymous_upgrade_disposals", migrations.TransactionModeDefault, anonymousUpgradeDisposalSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), m), nil
}

const anonymousUpgradeDisposalSQL = `ALTER TABLE identity.anonymous_disposals
 DROP CONSTRAINT anonymous_disposals_purpose_check,
 ADD CONSTRAINT anonymous_disposals_purpose_check CHECK(purpose IN ('identity.anonymous.delete','identity.anonymous.upgrade'));
`
