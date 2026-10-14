package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// VelocityIntentMigrationSource separates immutable attempt targets from
// post-mutation snapshots, so pending/unknown intent never fabricates counters.
// Version must permanently follow Base.Version. Existing history and snapshots
// are retained. Load is pure/concurrent-safe; installation grants no authority.
type VelocityIntentMigrationSource struct {
	Base    VelocityMigrationSource
	Version migrations.Version
}

var _ migrations.Source = VelocityIntentMigrationSource{}

// Load returns independently owned forward-only atomic history. Invalid input
// is redacted and base validation preserves cancellation and nil-context errors.
func (s VelocityIntentMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	h, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(velocityIntentSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_velocity_intent", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(h, m), nil
}

const velocityIntentSQL = `CREATE TABLE @schema@.velocity_targets(
 sequence bigint NOT NULL,phase text COLLATE "C" NOT NULL,window_us bigint NOT NULL,
 dimension text COLLATE "C" NOT NULL,
 PRIMARY KEY(sequence,dimension),
 FOREIGN KEY(sequence,phase,window_us) REFERENCES @schema@.velocity_attempts(sequence,phase,window_us),
 CHECK((phase='before_credential_or_provider_work' AND dimension IN('tenant','canonical_network','device','canonical_identifier_digest')) OR
       (phase='before_return' AND dimension IN('tenant','subject_or_network')))
);
INSERT INTO @schema@.velocity_targets SELECT sequence,phase,window_us,dimension FROM @schema@.velocity_snapshots;
ALTER TABLE @schema@.velocity_aliases DROP CONSTRAINT velocity_aliases_sequence_dimension_fkey;
ALTER TABLE @schema@.velocity_aliases ADD FOREIGN KEY(sequence,dimension) REFERENCES @schema@.velocity_targets;
ALTER TABLE @schema@.velocity_snapshots ADD FOREIGN KEY(sequence,dimension) REFERENCES @schema@.velocity_targets;
`
