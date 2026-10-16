package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// EmailVerificationSigninMigrationSource extends retained session issuance
// after MagicLinkSigninMigrationSource, or after MFASigninMigrationSource when
// MFASignin is true. Select the installed predecessor once and retain that
// immutable history; installing an older purpose migration afterward is invalid.
// Allocate a permanent unused Version in the same schema. Existing rows and
// commitment domains are unchanged. This creates no additional replay store.
type EmailVerificationSigninMigrationSource struct {
	Schema  string
	Version migrations.Version
	// MFASignin describes the already-installed v6 purpose constraint, not an
	// authentication-policy toggle. False preserves the v5 purpose set exactly.
	MFASignin bool
}

// Load constructs one forward-only transactional populated upgrade without IO.
// The runner owns locks, validation and commit. Each separately committed
// verification can parent at most one signin within its tenant. A nullable
// parent preserves all old issuances without inventing historical lineage.
func (s EmailVerificationSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_verification_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	prior := "v5"
	purposes := "'identity.session.issue','identity.otp.signin','identity.password.signin','identity.password.signup','identity.magic-link.consume'"
	if s.MFASignin {
		prior = "v6"
		purposes += ",'identity.mfa.totp-verify','identity.mfa.otp-verify','identity.mfa.recovery-use','identity.mfa.security-key-assert-verify'"
	}
	sql := strings.NewReplacer("@schema@", pgx.Identifier{s.Schema}.Sanitize(), "@prior@", prior, "@purposes@", purposes).Replace(verificationSigninSQL)
	m, err := migrations.NewMigration(s.Version, "identity_session_email_verification_signin", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const verificationSigninSQL = `ALTER TABLE @schema@.session_issuances DROP CONSTRAINT session_issuances_purpose_@prior@;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_v7 CHECK(purpose IN(@purposes@,'identity.email.verification-signin'));
ALTER TABLE @schema@.session_issuances ADD COLUMN verification_command_id bytea;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_verification_parent CHECK(
 (purpose = 'identity.email.verification-signin' AND verification_command_id IS NOT NULL AND octet_length(verification_command_id) = 16)
 OR (purpose <> 'identity.email.verification-signin' AND verification_command_id IS NULL));
CREATE UNIQUE INDEX session_issuances_verification_parent_unique ON @schema@.session_issuances(tenant_id,verification_command_id) WHERE verification_command_id IS NOT NULL;
`
