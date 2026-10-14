package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// VelocityActivationMigrationSource adds actual activation time separately
// from the immutable covered snapshot watermark in the existing epoch owner.
// Legacy healthy rows lack authenticated native activation provenance: they
// become unavailable, retaining all windows, journal facts and lockouts. No
// replaying row or confirmation is promoted. Allocate Version after Base.Version.
type VelocityActivationMigrationSource struct {
	Base    VelocityPublicationMigrationSource
	Version migrations.Version
}

var _ migrations.Source = VelocityActivationMigrationSource{}

// Load appends independently owned forward-only SQL without IO or rewriting
// installed history. Invalid allocation/context returns no migration history.
func (s VelocityActivationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	h, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(velocityActivationSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Base.Base.Base.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_velocity_activation", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(h, m), nil
}

const velocityActivationSQL = `ALTER TABLE @schema@.velocity_epochs ADD COLUMN activated_at timestamptz;
UPDATE @schema@.velocity_epochs SET state='unavailable',healthy_at=NULL WHERE state='healthy';
ALTER TABLE @schema@.velocity_epochs
 ADD CHECK(activated_at IS NULL OR isfinite(activated_at)),
 ADD CHECK(state<>'healthy' OR
 (activated_at IS NOT NULL AND publication_id IS NOT NULL AND publication_confirmed_at IS NOT NULL
 AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL AND journal_started_at IS NOT NULL
 AND healthy_at=replay_through AND publication_confirmed_at>=replay_through
 AND activated_at>=publication_confirmed_at AND activated_at<lease_expires_at
 AND journal_started_at<=replay_through-maximum_window_us*interval '1 microsecond'));
`
