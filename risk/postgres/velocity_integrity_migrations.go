package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// VelocityIntegrityMigrationSource adds full-record replay authentication after
// Base. Installed history is unchanged. Existing records remain unsealed: SQL
// cannot authenticate their original facts and must never invent that proof.
// They remain available for investigation, but cannot grant native readback or
// autonomous replay until an attributable recovery proves their original facts.
type VelocityIntegrityMigrationSource struct {
	Base    VelocityIntentMigrationSource
	Version migrations.Version
}

var _ migrations.Source = VelocityIntegrityMigrationSource{}

// Load returns independently owned forward-only history without IO. Invalid
// allocation is redacted; base context/schema validation remains unchanged.
func (s VelocityIntegrityMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	h, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(velocityIntegritySQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_velocity_integrity", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(h, m), nil
}

const velocityIntegritySQL = `ALTER TABLE @schema@.velocity_attempts ADD COLUMN replay_seal bytea
 CHECK(replay_seal IS NULL OR octet_length(replay_seal)=32);
`
