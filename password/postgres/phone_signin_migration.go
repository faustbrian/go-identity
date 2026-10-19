package passwordpostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhonePasswordSigninMigrationSource extends completed-password provenance with
// the distinct phone/password operation. Base is the installed password history;
// Version must follow it. UsernameSignin must match whether the username signin
// suffix was installed. A mismatched selection fails at migration, not by
// dropping unknown constraints or broadening the installed purpose profile.
// Existing signed records and migration checksums remain unchanged.
type PhonePasswordSigninMigrationSource struct {
	Base           migrations.Source
	Version        migrations.Version
	UsernameSignin bool
}

// Load copies Base and appends one irreversible purpose extension without IO.
func (s PhonePasswordSigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (UsernameSigninMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	constraint := "signin_records_purpose_check"
	purposes := "'identity.password.signin','identity.phone.password-signin'"
	if s.UsernameSignin {
		constraint = "signin_records_purpose_v2"
		purposes += ",'identity.username.signin'"
	}
	forward, err := migrations.NewMigration(s.Version, "identity_password_phone_signin", migrations.TransactionModeDefault,
		"ALTER TABLE identity_password.signin_records DROP CONSTRAINT "+constraint+";\n"+
			"ALTER TABLE identity_password.signin_records ADD CONSTRAINT signin_records_purpose_phone_v1 CHECK(purpose IN("+purposes+"));\n", "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}
