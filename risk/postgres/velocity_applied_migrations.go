package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// VelocityAppliedMigrationSource adds generation-bound acknowledged recovery
// progress to the existing epoch owner. Installation grants no applied progress
// or healthy state, and preserves every installed migration and journal fact.
type VelocityAppliedMigrationSource struct {
	Base    VelocityReplayMigrationSource
	Version migrations.Version
}

var _ migrations.Source = VelocityAppliedMigrationSource{}

// Load returns independent forward-only history without IO. Version must be
// allocated after Base.Version. Invalid input and cancellation return no SQL.
func (s VelocityAppliedMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	h, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(velocityAppliedSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_velocity_applied", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(h, m), nil
}

const velocityAppliedSQL = `ALTER TABLE @schema@.velocity_epochs
 ADD COLUMN applied_generation numeric,
 ADD COLUMN applied_position bigint NOT NULL DEFAULT 0,
 ADD COLUMN applied_seal bytea,
 ADD CHECK(applied_position>=0),
 ADD CHECK((applied_generation IS NULL AND applied_position=0 AND applied_seal IS NULL) OR
 (applied_generation IS NOT NULL AND applied_generation BETWEEN 1 AND generation AND scale(applied_generation)=0 AND applied_position>0 AND applied_seal IS NOT NULL AND octet_length(applied_seal)=32));
`
