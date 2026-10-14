package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// IssuanceIDMigrationSource appends the opaque command-identity profile without
// rewriting the original install or changing retained encrypted response AAD.
// Base is the original permanent allocation; Version must be a later permanent
// allocation within MaxInt64. Existing digest-target rows remain readable and
// unchanged, but new issuance uses only opaque command IDs. Load is pure and
// concurrent-safe; zero is invalid. There is no destructive down migration.
type IssuanceIDMigrationSource struct {
	Base    MigrationSource
	Version migrations.Version
}

var _ migrations.Source = IssuanceIDMigrationSource{}

// Load returns an owned complete forward history, preserving Base's exact SQL.
// Invalid allocation is redacted; context cancellation is preserved.
func (s IssuanceIDMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(issuanceIDSchemaSQL, "@schema@", pgx.Identifier{s.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_opaque_issuance_identity", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, m), nil
}

const issuanceIDSchemaSQL = `ALTER TABLE @schema@.issued_evidence
 DROP CONSTRAINT issued_evidence_record_id_check,
 ADD CONSTRAINT risk_issued_record_identity CHECK(
 record_id=translate(rtrim(encode(command_id,'base64'),'='),'+/','-_')
 OR record_id ~ '^rei1_[1-9][0-9]{0,9}_[A-Za-z0-9_-]{43}$'
 );`
