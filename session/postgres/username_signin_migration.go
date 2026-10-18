package postgres

import (
	"context"
	"math"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// UsernameSigninPredecessor identifies the already-installed purpose constraint,
// not an authentication policy. Installing older suffixes afterward is invalid.
type UsernameSigninPredecessor uint8

const (
	// UsernameSigninAfterPassword follows PasswordSigninMigrationSource.
	UsernameSigninAfterPassword UsernameSigninPredecessor = 3
	// UsernameSigninAfterSignup retains PasswordSignupMigrationSource purposes.
	UsernameSigninAfterSignup UsernameSigninPredecessor = 4
	// UsernameSigninAfterMagicLink retains MagicLinkSigninMigrationSource purposes.
	UsernameSigninAfterMagicLink UsernameSigninPredecessor = 5
	// UsernameSigninAfterMFA retains the factor-completion purpose profile.
	UsernameSigninAfterMFA UsernameSigninPredecessor = 6
	// UsernameSigninAfterVerification retains verification-only signin purposes.
	UsernameSigninAfterVerification UsernameSigninPredecessor = 7
	// UsernameSigninAfterVerificationMFA retains verification plus MFA purposes.
	UsernameSigninAfterVerificationMFA UsernameSigninPredecessor = 8
)

// UsernameSigninMigrationSource adds the exact username-signin purpose while
// preserving every installed predecessor purpose. Schema and Version are permanent
// explicit composition; the caller's migration runner owns locks and transactions.
type UsernameSigninMigrationSource struct {
	Schema      string
	Version     migrations.Version
	Predecessor UsernameSigninPredecessor
	// MFASignin records the MFA-before-verification variant of the installed
	// v7 constraint. It is valid only with UsernameSigninAfterVerification.
	// The verification-first v8 predecessor already includes MFA unambiguously.
	MFASignin bool
}

// Load builds one forward-only suffix. It changes no existing issuance or bytes.
func (s UsernameSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) || s.Predecessor < 3 || s.Predecessor > 8 || s.MFASignin && s.Predecessor != UsernameSigninAfterVerification {
		return nil, identity.InvalidInputError{Field: "session_username_signin_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	purposes := "'identity.session.issue','identity.otp.signin','identity.password.signin','identity.username.signin'"
	if s.Predecessor >= 4 {
		purposes += ",'identity.password.signup'"
	}
	if s.Predecessor >= 5 {
		purposes += ",'identity.magic-link.consume'"
	}
	if s.Predecessor == 6 || s.Predecessor == 8 || s.MFASignin {
		purposes += ",'identity.mfa.totp-verify','identity.mfa.otp-verify','identity.mfa.recovery-use','identity.mfa.security-key-assert-verify'"
	}
	if s.Predecessor >= 7 {
		purposes += ",'identity.email.verification-signin'"
	}
	sql := strings.NewReplacer("@schema@", pgx.Identifier{s.Schema}.Sanitize(), "@prior@", strconv.Itoa(int(s.Predecessor)), "@purposes@", purposes).Replace(`ALTER TABLE @schema@.session_issuances DROP CONSTRAINT session_issuances_purpose_v@prior@;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_username_v1 CHECK(purpose IN(@purposes@));
`)
	m, err := migrations.NewMigration(s.Version, "identity_session_username_signin", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}
