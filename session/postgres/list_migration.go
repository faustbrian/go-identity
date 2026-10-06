package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ListMigrationSource is the forward-only, independently composed audience-page
// index. Schema must match the installed base; Version is its permanently
// allocated 1..MaxInt64 history slot after the base install. Load performs no IO.
// Install through the sole migrations Runner: the transactional index build can
// block session writes until complete, so size and schedule populated deployments
// explicitly. No record, base checksum or authority is rewritten; no destructive
// rollback is provided. Calls are safe concurrently and return owned migrations.
type ListMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns the bounded-query supporting index; nil or cancelled context and
// invalid schema/version fail before composition. Duplicate/unmanaged indexes
// fail at install rather than silently being adopted.
func (s ListMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_list_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_session_list_index", migrations.TransactionModeDefault, `CREATE INDEX session_owner_audience_order ON `+pgx.Identifier{s.Schema}.Sanitize()+`.sessions(tenant_id,user_id,((record->>'Audience') COLLATE "C"),session_id);`, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}
