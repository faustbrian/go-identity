package postgres

import (
	"context"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PhoneOTPSigninMigrationSource admits the distinct phone SMS-code signin
// purpose after an explicitly selected installed purpose history. Predecessor
// and MFASignin have UsernameSigninMigrationSource semantics. UsernameSignin
// and PhonePasswordSignin identify already-installed optional suffixes, not
// dependencies on those authentication methods. Install this last among the
// selected purpose suffixes; no existing issuance or installed SQL is rewritten.
type PhoneOTPSigninMigrationSource struct {
	Schema              string
	Version             migrations.Version
	Predecessor         UsernameSigninPredecessor
	MFASignin           bool
	UsernameSignin      bool
	PhonePasswordSignin bool
}

// Load returns one forward-only transactional migration. The caller owns the
// runner and transaction. A wrong predecessor fails at the installed constraint
// rather than guessing a broader profile. This enables no login endpoint.
func (s PhoneOTPSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if _, err := (UsernameSigninMigrationSource{Schema: s.Schema, Version: s.Version, Predecessor: s.Predecessor, MFASignin: s.MFASignin}).Load(ctx); err != nil {
		return nil, err
	}
	constraint := "session_issuances_purpose_v" + strconv.Itoa(int(s.Predecessor))
	purposes := "'identity.session.issue','identity.otp.signin','identity.password.signin','identity.phone.signin'"
	if s.UsernameSignin {
		constraint = "session_issuances_purpose_username_v1"
		purposes += ",'identity.username.signin'"
	}
	if s.PhonePasswordSignin {
		constraint = "session_issuances_purpose_phone_password_v1"
		purposes += ",'identity.phone.password-signin'"
	}
	if s.Predecessor >= UsernameSigninAfterSignup {
		purposes += ",'identity.password.signup'"
	}
	if s.Predecessor >= UsernameSigninAfterMagicLink {
		purposes += ",'identity.magic-link.consume'"
	}
	if s.Predecessor == UsernameSigninAfterMFA || s.Predecessor == UsernameSigninAfterVerificationMFA || s.MFASignin {
		purposes += ",'identity.mfa.totp-verify','identity.mfa.otp-verify','identity.mfa.recovery-use','identity.mfa.security-key-assert-verify'"
	}
	if s.Predecessor >= UsernameSigninAfterVerification {
		purposes += ",'identity.email.verification-signin'"
	}
	sql := strings.NewReplacer("@schema@", pgx.Identifier{s.Schema}.Sanitize(), "@prior@", constraint, "@purposes@", purposes).Replace(`ALTER TABLE @schema@.session_issuances DROP CONSTRAINT @prior@;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_phone_otp_v1 CHECK(purpose IN(@purposes@));
`)
	m, err := migrations.NewMigration(s.Version, "identity_session_phone_otp_signin", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}
