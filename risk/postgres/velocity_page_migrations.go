package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// VelocityReplayMigrationSource adds native change ordering after integrity
// history. Installation never signs existing rows or grants replay progress.
// Valid original seals are required for bounded native initialization at read.
type VelocityReplayMigrationSource struct {
	Base    VelocityIntegrityMigrationSource
	Version migrations.Version
}

var _ migrations.Source = VelocityReplayMigrationSource{}

// Load returns independent forward-only history without IO. Installed SQL is
// unchanged; invalid allocations, nil context and cancellation fail redacted.
func (s VelocityReplayMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	h, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(velocityReplaySQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_velocity_replay", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(h, m), nil
}

const velocityReplaySQL = `CREATE SEQUENCE @schema@.velocity_replay_position AS bigint MINVALUE 1 NO CYCLE;
ALTER TABLE @schema@.velocity_attempts ADD COLUMN replay_position bigint,
 ADD COLUMN position_seal bytea,
 ADD CHECK((replay_position IS NULL AND position_seal IS NULL) OR
 (replay_position IS NOT NULL AND replay_position>0 AND position_seal IS NOT NULL AND octet_length(position_seal)=32));
CREATE UNIQUE INDEX risk_velocity_position_unique ON @schema@.velocity_attempts(replay_position) WHERE replay_position IS NOT NULL;
CREATE INDEX risk_velocity_position_scan ON @schema@.velocity_attempts(tenant_id,namespace_digest,replay_position) WHERE replay_position IS NOT NULL;
CREATE INDEX risk_velocity_position_init ON @schema@.velocity_attempts(tenant_id,namespace_digest,sequence) WHERE replay_position IS NULL;
`
