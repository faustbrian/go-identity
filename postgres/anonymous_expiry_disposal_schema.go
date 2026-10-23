package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// AnonymousExpiryDisposalMigrationSource appends the exact service-expiry
// purpose after the selected kernel disposal history. Install optional upgrade
// purpose extensions first: this suffix preserves their admission but does not
// enable an upgrade workflow. Existing SQL and populated evidence are unchanged.
// No destructive downgrade or automatic migration is provided.
type AnonymousExpiryDisposalMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load validates the selected increasing history without IO. The existing
// migration runner owns installation. Missing, duplicated or out-of-order
// disposal histories and cancellation fail closed.
func (s AnonymousExpiryDisposalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "anonymous_expiry_disposal_migration"}
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
	found, upgrade := false, false
	for _, m := range history {
		if m.Version() >= s.Version || m.Name() == "identity_anonymous_expiry_disposals" {
			return nil, invalid
		}
		found = found || m.Name() == "identity_anonymous_disposals"
		upgrade = upgrade || m.Name() == "identity_anonymous_upgrade_disposals"
	}
	if !found {
		return nil, invalid
	}
	purposes := "'identity.anonymous.delete','identity.anonymous.expire'"
	if upgrade {
		purposes += ",'identity.anonymous.upgrade'"
	}
	sql := strings.ReplaceAll(anonymousExpiryDisposalSQL, "@purposes@", purposes)
	m, err := migrations.NewMigration(s.Version, "identity_anonymous_expiry_disposals", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), m), nil
}

const anonymousExpiryDisposalSQL = `ALTER TABLE identity.anonymous_disposals
 DROP CONSTRAINT anonymous_disposals_purpose_check,
 ADD CONSTRAINT anonymous_disposals_purpose_check CHECK(purpose IN (@purposes@));
`
