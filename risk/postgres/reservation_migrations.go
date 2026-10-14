package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// ReservationMigrationSource appends one-use journal ownership to the complete
// issuance history. Allocate Version permanently after Base.Version in the
// composition's single history. Existing rows retain their original identity,
// expiry and encrypted response; no owner is invented. The schema permits the
// six journal states but does not authorize their transitions. Only the native
// participant inside the sole coordinator may mutate them. Load is pure and
// concurrent-safe; zero is invalid. No destructive down migration is provided.
type ReservationMigrationSource struct {
	Base    IssuanceIDMigrationSource
	Version migrations.Version
}

var _ migrations.Source = ReservationMigrationSource{}

// Load returns independently owned complete forward history without rewriting
// installed SQL. Invalid allocation is redacted and cancellation is preserved.
func (s ReservationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.Base.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(reservationSchemaSQL, "@schema@", pgx.Identifier{s.Base.Base.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_evidence_reservation", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(history, m), nil
}

// Ownership is all-or-none, preserving unresolved generations in terminal
// tombstones. A composite command FK forbids cross-tenant ownership and keeps
// command retirement from destroying reconciliation linkage. Generation is an
// exact uint64 scalar, not a PostgreSQL signed-bigint truncation.
const reservationSchemaSQL = `ALTER TABLE @schema@.issued_evidence
 DROP CONSTRAINT issued_evidence_state_check,
 ADD COLUMN reservation_command_id bytea,
 ADD COLUMN reservation_purpose text COLLATE "C",
 ADD COLUMN reservation_fingerprint bytea,
 ADD COLUMN reservation_generation numeric,
 ADD COLUMN reserved_at timestamptz,
 ADD CONSTRAINT risk_evidence_state CHECK(state IN('issued','reserved','finalized','released','expired','revoked')),
 ADD CONSTRAINT risk_reservation_complete CHECK(
 num_nonnulls(reservation_command_id,reservation_purpose,reservation_fingerprint,reservation_generation,reserved_at) IN(0,5)),
 ADD CONSTRAINT risk_reservation_state CHECK(
 (state IN('issued','expired') AND reservation_command_id IS NULL)
 OR (state IN('reserved','finalized','released') AND reservation_command_id IS NOT NULL)
 OR state='revoked'),
 ADD CONSTRAINT risk_reservation_identity CHECK(reservation_command_id IS NULL OR
 (octet_length(reservation_command_id)=16 AND reservation_command_id<>command_id
 AND reservation_command_id<>decode(repeat('00',16),'hex'))),
 ADD CONSTRAINT risk_reservation_purpose CHECK(reservation_purpose IS NULL OR
 (purpose='phone-password-reset-initiate' AND reservation_purpose='identity.phone.password-reset-request') OR
 (purpose='phone-password-reset-complete' AND reservation_purpose='identity.phone.password-reset-complete')),
 ADD CONSTRAINT risk_reservation_fingerprint CHECK(reservation_fingerprint IS NULL OR
 (octet_length(reservation_fingerprint)=32 AND reservation_fingerprint<>decode(repeat('00',32),'hex'))),
 ADD CONSTRAINT risk_reservation_generation CHECK(reservation_generation IS NULL OR
 (reservation_generation>=1 AND reservation_generation<=18446744073709551615 AND scale(reservation_generation)=0)),
 ADD CONSTRAINT risk_reservation_time CHECK(reserved_at IS NULL OR
 (isfinite(reserved_at) AND reserved_at>=issued_at AND reserved_at<expires_at)),
 ADD CONSTRAINT risk_reservation_command FOREIGN KEY(reservation_command_id,tenant_id,reservation_purpose)
 REFERENCES identity.commands(command_id,tenant_id,purpose);
CREATE INDEX risk_reserved_command_order ON @schema@.issued_evidence(tenant_id,reservation_command_id,record_id)
 WHERE reservation_command_id IS NOT NULL;
`
