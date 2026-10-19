package postgres

import (
	"context"
	"strconv"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// PhonePasswordSigninMigrationSource adds phone/password session provenance to
// an explicitly selected installed purpose profile. Predecessor and MFASignin
// have UsernameSigninMigrationSource semantics. UsernameSignin selects the
// already-installed username suffix over that predecessor; it is not a dependency
// on username login. Install this after all selected predecessor purpose suffixes.
// No existing row, authentication, deadline or installed checksum is rewritten.
type PhonePasswordSigninMigrationSource struct {
	Schema         string
	Version        migrations.Version
	Predecessor    UsernameSigninPredecessor
	MFASignin      bool
	UsernameSignin bool
}

// Load returns a single forward-only migration; caller owns its transaction and
// runner. An incorrectly selected installed constraint fails rather than guessing
// or admitting unrelated methods. This does not expose a phone signin endpoint.
func (s PhonePasswordSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	// Validate the exact shared predecessor union without altering its historical
	// SQL. The phone extension generates its own permanently named suffix below.
	if _, err := (UsernameSigninMigrationSource{Schema: s.Schema, Version: s.Version, Predecessor: s.Predecessor, MFASignin: s.MFASignin}).Load(ctx); err != nil {
		return nil, err
	}
	constraint := "session_issuances_purpose_v" + strconv.Itoa(int(s.Predecessor))
	purposes := "'identity.session.issue','identity.otp.signin','identity.password.signin','identity.phone.password-signin'"
	if s.UsernameSignin {
		constraint = "session_issuances_purpose_username_v1"
		purposes += ",'identity.username.signin'"
	}
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
	sql := strings.NewReplacer("@schema@", pgx.Identifier{s.Schema}.Sanitize(), "@prior@", constraint, "@purposes@", purposes).Replace(`ALTER TABLE @schema@.session_issuances DROP CONSTRAINT @prior@;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_phone_password_v1 CHECK(purpose IN(@purposes@));
`)
	m, err := migrations.NewMigration(s.Version, "identity_session_phone_password_signin", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}
