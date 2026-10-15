package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// EmailChangeCounterMigrationSource appends the closed change-confirm grant
// dimension to already installed protected counters. Allocate Version after
// selected histories; populated windows and their time/charges are unchanged.
// Existing check expression is retained exactly, including selected MFA/browser
// lanes. Missing/unvalidated owned checks fail, not silently rebuild storage.
// This forward transactional migration owns no runtime resources or authority.
type EmailChangeCounterMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns the bounded pure migration; cancellation and invalid input deny.
func (s EmailChangeCounterMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(emailChangeCounterSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_email_change_counters", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const emailChangeCounterSQL = `DO $migration$
DECLARE original text;
BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO STRICT original FROM pg_constraint
 WHERE conrelid='@schema@.counter_windows'::regclass AND conname='counter_windows_dimension_check' AND contype='c' AND convalidated;
 ALTER TABLE @schema@.counter_windows DROP CONSTRAINT counter_windows_dimension_check;
 EXECUTE format('ALTER TABLE @schema@.counter_windows ADD CONSTRAINT counter_windows_dimension_check CHECK ((%s) OR (dimension=''capability'' AND operation=''identity.email.change-confirm''))',original);
 SELECT pg_get_expr(conbin,conrelid) INTO STRICT original FROM pg_constraint
 WHERE conrelid='@schema@.counter_snapshots'::regclass AND conname='counter_snapshots_dimension_check' AND contype='c' AND convalidated;
 ALTER TABLE @schema@.counter_snapshots DROP CONSTRAINT counter_snapshots_dimension_check;
 EXECUTE format('ALTER TABLE @schema@.counter_snapshots ADD CONSTRAINT counter_snapshots_dimension_check CHECK ((%s) OR dimension=''capability'')',original);
END
$migration$;
`
