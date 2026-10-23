package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// AnonymousExpiryMigrationSource appends service-expiry evidence support after
// the installed anonymous-disposal history. Upgrade must exactly describe the
// optional already-installed upgrade suffix; install expiry last among these
// purpose extensions. The source changes no predecessor bytes or live records.
// Only service expiry permits absent source IDs and zero revocation counts.
type AnonymousExpiryMigrationSource struct {
	Schema  string
	Version migrations.Version
	Upgrade bool
}

// Load returns one forward-only suffix without IO. Installation against the
// wrong predecessor constraint fails rather than silently adopting its profile.
// The caller permanently allocates Version after all selected predecessors.
func (s AnonymousExpiryMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_anonymous_expiry_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	constraint := "anonymous_disposals_purpose_check"
	purposes := "'identity.anonymous.delete'"
	if s.Upgrade {
		constraint = "anonymous_disposals_purpose_upgrade_v1"
		purposes += ",'identity.anonymous.upgrade'"
	}
	sql := strings.NewReplacer("@schema@", pgx.Identifier{s.Schema}.Sanitize(), "@constraint@", constraint, "@purposes@", purposes).Replace(anonymousExpirySessionSQL)
	m, err := migrations.NewMigration(s.Version, "identity_session_anonymous_expiry", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{m}, nil
}

const anonymousExpirySessionSQL = `ALTER TABLE @schema@.anonymous_disposals
 DROP CONSTRAINT @constraint@,
 DROP CONSTRAINT anonymous_disposals_revoked_count_check,
 DROP CONSTRAINT anonymous_disposals_family_count_check,
 ALTER COLUMN source_id DROP NOT NULL,
 ADD CONSTRAINT anonymous_disposals_revoked_count_check CHECK(revoked_count BETWEEN 0 AND 100000),
 ADD CONSTRAINT anonymous_disposals_family_count_check CHECK(family_count BETWEEN 0 AND 100000),
 ADD CONSTRAINT anonymous_disposals_purpose_expiry_v1 CHECK(
   (purpose='identity.anonymous.expire' AND source_id IS NULL) OR
   (purpose IN(@purposes@) AND source_id IS NOT NULL AND revoked_count>0 AND family_count>0)
 );
`
