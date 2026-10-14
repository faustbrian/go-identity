package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFASigninMigrationSource extends the existing retained issuance purpose
// constraint after MagicLinkSigninMigrationSource. Allocate an unused permanent
// Version in that same schema/history. It preserves rows and commitment domains
// and creates no replay table. The closed factor-completion purposes are not
// proof of authentication; native owners must commit all required factor effects.
type MFASigninMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only transactional extension without IO. The
// existing runner owns locks, populated-state validation and commit. Invalid
// owner/configuration is redacted and cancellation/deadlines are preserved.
func (s MFASigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_mfa_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sql := strings.ReplaceAll(mfaSigninSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize())
	m, err := migrations.NewMigration(s.Version, "identity_session_mfa_signin", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const mfaSigninSQL = `ALTER TABLE @schema@.session_issuances DROP CONSTRAINT session_issuances_purpose_v5;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_v6 CHECK(purpose IN('identity.session.issue','identity.otp.signin','identity.password.signin','identity.password.signup','identity.magic-link.consume','identity.mfa.totp-verify','identity.mfa.otp-verify','identity.mfa.recovery-use','identity.mfa.security-key-assert-verify'));
`
