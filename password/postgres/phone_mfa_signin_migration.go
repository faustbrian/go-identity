package passwordpostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhoneMFASigninMigrationSource admits the exact phone-password operation to
// the existing non-final primary store. Base is installed password history and
// Version must follow it. UsernameMFA selects whether Base installed that suffix;
// a mismatch fails at migration rather than dropping unknown constraints.
// Original migration checksums, signed records and command custody are unchanged.
type PhoneMFASigninMigrationSource struct {
	Base        migrations.Source
	Version     migrations.Version
	UsernameMFA bool
}

// Load copies Base and appends one irreversible purpose extension without IO.
func (s PhoneMFASigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (UsernameSigninMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	constraint := "mfa_primary_records_purpose_check"
	purposes := "'identity.password.signin','identity.phone.password-signin'"
	if s.UsernameMFA {
		constraint = "mfa_primary_records_purpose_v2"
		purposes += ",'identity.username.signin'"
	}
	forward, err := migrations.NewMigration(s.Version, "identity_password_phone_mfa_signin", migrations.TransactionModeDefault,
		"ALTER TABLE identity_password.mfa_primary_records DROP CONSTRAINT "+constraint+";\n"+
			"ALTER TABLE identity_password.mfa_primary_records ADD CONSTRAINT mfa_primary_records_purpose_phone_v1 CHECK(purpose IN("+purposes+"));\n", "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}
