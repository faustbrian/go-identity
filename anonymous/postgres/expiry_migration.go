package anonymouspostgres

import (
	"context"
	"math"
	"strings"

	"github.com/faustbrian/go-identity/anonymous"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ExpiryMigrationSource appends service-expiry support to the installed
// anonymous disposal journal. Existing creation/deletion/upgrade SQL and rows
// are unchanged. Expired delete is distinct from requested self-deletion;
// anonymize and retain preserve their stored-policy terminal classifications.
// Allocate Version after selected predecessors; no destructive downgrade exists.
type ExpiryMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only suffix without IO or capability activation.
// Wrong/missing predecessor constraints fail when the existing runner installs
// the suffix. Nil contexts, invalid schema/version and cancellation deny.
func (s ExpiryMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, anonymous.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_anonymous_expiry_disposals", migrations.TransactionModeDefault, strings.ReplaceAll(expiryDisposalSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{m}, nil
}

const expiryDisposalSQL = `ALTER TABLE @schema@.disposals
 DROP CONSTRAINT disposals_purpose_check,
 DROP CONSTRAINT disposals_check1,
 ADD CONSTRAINT disposals_purpose_expiry_v1 CHECK(purpose IN('identity.anonymous.delete','identity.anonymous.expire')),
 ADD CONSTRAINT disposals_terminal_expiry_v1 CHECK(
   (cleanup=1 AND ((purpose='identity.anonymous.delete' AND terminal_state=3) OR (purpose='identity.anonymous.expire' AND terminal_state=4))) OR
   (cleanup=2 AND terminal_state=5) OR
   (cleanup=3 AND terminal_state=6)
 );
`
