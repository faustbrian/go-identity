package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// VelocityCoverageMigrationSource adds primary journal lifetime metadata to the
// existing epoch owner. Existing epochs remain unknown; new epochs start at
// insertion time, never one window in the past. No health is installed.
type VelocityCoverageMigrationSource struct {
	Base    VelocityAppliedMigrationSource
	Version migrations.Version
}

var _ migrations.Source = VelocityCoverageMigrationSource{}

// Load appends independent forward-only history. Allocate Version permanently
// after Base.Version; cancellation and invalid input return no SQL.
func (s VelocityCoverageMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	h, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(velocityCoverageSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Base.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_velocity_coverage", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(h, m), nil
}

const velocityCoverageSQL = `ALTER TABLE @schema@.velocity_epochs
 ADD COLUMN journal_started_at timestamptz,
 ADD CHECK(journal_started_at IS NULL OR isfinite(journal_started_at));
ALTER TABLE @schema@.velocity_epochs ALTER COLUMN journal_started_at SET DEFAULT clock_timestamp();
`
