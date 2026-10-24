package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PasskeySignupCounterMigrationSource adds only the two canonical registration
// actions' browser-flow/device dimensions. Allocate Version after all selected
// histories. Installed validated expressions are preserved, including optional
// MFA, email and verification profiles; no window, charge or snapshot is reset.
// Missing or unvalidated owned checks fail atomically. This selects storage,
// not browser authentication, risk allowance or native registration authority.
type PasskeySignupCounterMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one pure forward transactional migration. Invalid schema/version,
// nil context and cancellation fail before SQL construction. Calls are safe
// concurrently and own no runtime resources.
func (s PasskeySignupCounterMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "risk_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(passkeySignupCounterSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_risk_passkey_signup_counters", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const passkeySignupCounterSQL = `DO $migration$
DECLARE original text;
BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO STRICT original FROM pg_constraint
 WHERE conrelid='@schema@.counter_windows'::regclass AND conname='counter_windows_dimension_check' AND contype='c' AND convalidated
 AND (SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname='dimension' AND NOT attisdropped)=ANY(conkey)
 AND conkey <@ ARRAY(SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname IN('dimension','operation') AND NOT attisdropped);
 ALTER TABLE @schema@.counter_windows DROP CONSTRAINT counter_windows_dimension_check;
 EXECUTE format('ALTER TABLE @schema@.counter_windows ADD CONSTRAINT counter_windows_dimension_check CHECK ((%s) OR (dimension IN(''browser-flow'',''device'') AND operation IN(''identity.passkey.register-options'',''identity.passkey.register-verify'')))',original);
 SELECT pg_get_expr(conbin,conrelid) INTO STRICT original FROM pg_constraint
 WHERE conrelid='@schema@.counter_snapshots'::regclass AND conname='counter_snapshots_dimension_check' AND contype='c' AND convalidated
 AND conkey=ARRAY(SELECT attnum FROM pg_attribute WHERE attrelid=conrelid AND attname='dimension' AND NOT attisdropped);
 ALTER TABLE @schema@.counter_snapshots DROP CONSTRAINT counter_snapshots_dimension_check;
 EXECUTE format('ALTER TABLE @schema@.counter_snapshots ADD CONSTRAINT counter_snapshots_dimension_check CHECK ((%s) OR dimension IN(''browser-flow'',''device''))',original);
END
$migration$;
`
