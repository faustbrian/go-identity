package passwordpostgres

import (
	"context"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// EmailReauthenticationMigrationSource selects the additive email-consumption
// extension of the existing password history in identity_password. Install it
// before email protected use. Base MigrationSource and its eight installed
// checksums remain unchanged; this source includes those predecessors followed
// by version 9. The zero value is usable. Load performs no IO or destructive
// downgrade and grants no authority to consume a proof or change an address.
type EmailReauthenticationMigrationSource struct{}

var _ migrations.Source = EmailReauthenticationMigrationSource{}

// Load returns the complete selected forward-only history. Existing consumed
// password/MFA records, command foreign keys and one-use uniqueness are retained.
func (EmailReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (MigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	addition, err := migrations.NewMigration(9, "identity_password_email_reauthentication_consumption", migrations.TransactionModeDefault, emailReauthenticationConsumptionSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return append(history, addition), nil
}

const emailReauthenticationConsumptionSQL = `ALTER TABLE identity_password.reauthentication_records
 DROP CONSTRAINT reauthentication_consumption_complete,
 ADD CONSTRAINT reauthentication_consumption_complete CHECK (
  (consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL)
  OR (consumed_command_id IS NOT NULL AND octet_length(consumed_command_id)=16
   AND consumed_purpose IS NOT NULL AND consumed_purpose IN (
    'identity.password.change','identity.mfa.enable','identity.email.verification-send',
    'identity.email.change-request','identity.email.address-remove')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
