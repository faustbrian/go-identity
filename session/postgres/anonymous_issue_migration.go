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

// AnonymousIssuancePredecessor names the actually installed session-issuance
// purpose constraint. It selects migration history, never authentication policy.
type AnonymousIssuancePredecessor uint8

const (
	// AnonymousAfterBaseIssuance needs no password, OTP or other login method.
	AnonymousAfterBaseIssuance AnonymousIssuancePredecessor = 1
	// AnonymousAfterOTP preserves the installed OTP-only purpose extension.
	AnonymousAfterOTP AnonymousIssuancePredecessor = 2
	// AnonymousAfterPassword preserves the password-signin extension.
	AnonymousAfterPassword AnonymousIssuancePredecessor = 3
	// AnonymousAfterSignup preserves the password-signup extension.
	AnonymousAfterSignup AnonymousIssuancePredecessor = 4
	// AnonymousAfterMagicLink preserves the magic-link extension.
	AnonymousAfterMagicLink AnonymousIssuancePredecessor = 5
	// AnonymousAfterMFA preserves the MFA-before-verification extension.
	AnonymousAfterMFA AnonymousIssuancePredecessor = 6
	// AnonymousAfterVerification preserves the verification extension. MFASignin
	// additionally identifies its optional MFA-before-verification predecessor.
	AnonymousAfterVerification AnonymousIssuancePredecessor = 7
	// AnonymousAfterVerificationMFA preserves verification-first plus MFA.
	AnonymousAfterVerificationMFA AnonymousIssuancePredecessor = 8
)

// AnonymousSigninMigrationSource appends the exact anonymous purpose to an
// explicitly selected installed issuance history. Optional suffix flags describe
// already installed histories, not mandatory login dependencies. Install last
// among selected purpose extensions; installing an older suffix afterward is
// invalid. Version is permanent and later than every supplied history version.
// No installed SQL, session record or retained issuance digest is rewritten.
type AnonymousSigninMigrationSource struct {
	Schema              string
	Version             migrations.Version
	Predecessor         AnonymousIssuancePredecessor
	MFASignin           bool
	UsernameSignin      bool
	PhonePasswordSignin bool
	PhoneOTPSignin      bool
}

// Load returns one transactional forward suffix without IO. Wrong predecessor
// selection fails at the named installed constraint, never guesses or adopts
// another schema profile. The existing migration runner owns locks/commit.
func (s AnonymousSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "session_anonymous_signin_migration"}
	if ctx == nil || !validSchema(s.Schema) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) || s.Predecessor < 1 || s.Predecessor > 8 || s.MFASignin && s.Predecessor != AnonymousAfterVerification || (s.UsernameSignin || s.PhonePasswordSignin || s.PhoneOTPSignin) && s.Predecessor < AnonymousAfterPassword {
		return nil, invalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	constraint, purposes := anonymousIssuanceHistory(s)
	sql := strings.NewReplacer("@schema@", pgx.Identifier{s.Schema}.Sanitize(), "@prior@", constraint, "@purposes@", purposes).Replace(`ALTER TABLE @schema@.session_issuances DROP CONSTRAINT @prior@;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_anonymous_v1 CHECK(purpose IN(@purposes@));
`)
	step, err := migrations.NewMigration(s.Version, "identity_session_anonymous_signin", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{step}, nil
}

// Share only the selected installed purpose set. Forward extensions must not
// guess which optional histories were installed or rewrite their SQL/checksums.
func anonymousIssuanceHistory(s AnonymousSigninMigrationSource) (string, string) {
	constraint := "session_issuances_purpose_check"
	if s.Predecessor > 1 {
		constraint = "session_issuances_purpose_v" + strconv.Itoa(int(s.Predecessor))
	}
	purposes := "'identity.session.issue','identity.anonymous.signin'"
	if s.Predecessor >= AnonymousAfterOTP {
		purposes += ",'identity.otp.signin'"
	}
	if s.Predecessor >= AnonymousAfterPassword {
		purposes += ",'identity.password.signin'"
	}
	if s.Predecessor >= AnonymousAfterSignup {
		purposes += ",'identity.password.signup'"
	}
	if s.Predecessor >= AnonymousAfterMagicLink {
		purposes += ",'identity.magic-link.consume'"
	}
	if s.Predecessor == AnonymousAfterMFA || s.Predecessor == AnonymousAfterVerificationMFA || s.MFASignin {
		purposes += ",'identity.mfa.totp-verify','identity.mfa.otp-verify','identity.mfa.recovery-use','identity.mfa.security-key-assert-verify'"
	}
	if s.Predecessor >= AnonymousAfterVerification {
		purposes += ",'identity.email.verification-signin'"
	}
	if s.UsernameSignin {
		constraint = "session_issuances_purpose_username_v1"
		purposes += ",'identity.username.signin'"
	}
	if s.PhonePasswordSignin {
		constraint = "session_issuances_purpose_phone_password_v1"
		purposes += ",'identity.phone.password-signin'"
	}
	if s.PhoneOTPSignin {
		constraint = "session_issuances_purpose_phone_otp_v1"
		purposes += ",'identity.phone.signin'"
	}
	return constraint, purposes
}
