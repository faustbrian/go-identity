package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// VelocityPublicationMigrationSource records native cut confirmation in the
// existing epoch authority. Existing rows remain unconfirmed; installation
// grants neither health nor admission. Allocate Version after Base.Version.
type VelocityPublicationMigrationSource struct {
	Base    VelocityCoverageMigrationSource
	Version migrations.Version
}

var _ migrations.Source = VelocityPublicationMigrationSource{}

// Load appends independent forward-only history without IO. Invalid allocations,
// nil context and cancellation return no SQL and preserve base history.
func (s VelocityPublicationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	h, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(velocityPublicationSQL, "@schema@", pgx.Identifier{s.Base.Base.Base.Base.Base.Base.Base.Base.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_velocity_publication", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(h, m), nil
}

const velocityPublicationSQL = `ALTER TABLE @schema@.velocity_epochs
 ADD COLUMN publication_id bytea,
 ADD COLUMN publication_confirmed_at timestamptz,
 ADD CHECK((publication_id IS NULL AND publication_confirmed_at IS NULL) OR
 (publication_id IS NOT NULL AND octet_length(publication_id)=32 AND
 publication_id<>decode(repeat('00',32),'hex') AND publication_confirmed_at IS NOT NULL AND isfinite(publication_confirmed_at)));
`
