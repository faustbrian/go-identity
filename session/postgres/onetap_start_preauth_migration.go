package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// OneTapStartPreAuthMigrationSource extends the existing issuance evidence
// table to the exact One Tap start operation. Install after
// PreAuthIssueMigrationSource and before enabling the new native writer.
// Allocate two permanent ordered versions: a short metadata update, followed
// by validation in a separate transaction. Existing writers and rows remain
// compatible. No backfill or downgrade is provided.
type OneTapStartPreAuthMigrationSource struct {
	Schema            string
	Version           migrations.Version
	ValidationVersion migrations.Version
}

// Load returns both forward schema steps without I/O. Use the existing
// migrations runner so each step ends before the next lock is acquired.
func (s OneTapStartPreAuthMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.ValidationVersion <= s.Version || s.ValidationVersion > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_onetap_start_preauth_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	schema := pgx.Identifier{s.Schema}.Sanitize()
	expand, err := migrations.NewMigration(s.Version, "identity_session_onetap_start_preauth", migrations.TransactionModeDefault, strings.ReplaceAll(oneTapStartPreAuthExpandSQL, "@schema@", schema), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	validate, err := migrations.NewMigration(s.ValidationVersion, "identity_session_onetap_start_preauth_validate", migrations.TransactionModeDefault, strings.ReplaceAll(oneTapStartPreAuthValidateSQL, "@schema@", schema), "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{expand, validate}, nil
}

// The old constraint is stricter, so existing rows satisfy the replacement
// without rewriting or scanning while the metadata lock is held. NOT VALID
// still enforces the new contract on writes; the next step marks history valid.
const oneTapStartPreAuthExpandSQL = `SET LOCAL lock_timeout = '5s';
ALTER TABLE @schema@.preauth_issuances
 DROP CONSTRAINT preauth_issuances_purpose_check,
 ADD CONSTRAINT preauth_issuances_purpose_check
 CHECK (purpose IN ('identity.session.preauth-issue','identity.oauth.onetap-start')) NOT VALID;`

const oneTapStartPreAuthValidateSQL = `SET LOCAL lock_timeout = '5s';
ALTER TABLE @schema@.preauth_issuances VALIDATE CONSTRAINT preauth_issuances_purpose_check;`
