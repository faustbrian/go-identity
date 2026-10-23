package passwordpostgres

import (
	"context"

	"github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PasskeyDeletionReauthenticationMigrationSource appends exact self-deletion
// proof consumption to the password-owned one-use marker. Base must include
// PasskeyReauthenticationMigrationSource and every installed selected suffix,
// including management when installed. Version follows them all. Existing
// signed rows, foreign keys and unique consumption identity remain unchanged;
// no native deletion or recovery policy is enabled by installing this suffix.
type PasskeyDeletionReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load copies the forward-only history without IO. Missing enrollment history,
// invalid versions and nil/canceled contexts return no partial history. No
// destructive rollback is offered; management need not be selected at runtime.
func (s PasskeyDeletionReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (PasskeyManagementReauthenticationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_password_passkey_deletion_reauthentication_consumption", migrations.TransactionModeDefault, passkeyDeletionReauthenticationSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	history[len(history)-1] = step
	return history, nil
}

// Published enrollment/rename SQL stays immutable. The exact delete action is
// consumed only by its genuine native primary within the protected transaction.
const passkeyDeletionReauthenticationSQL = `ALTER TABLE identity_password.reauthentication_records
 DROP CONSTRAINT reauthentication_consumption_complete,
 ADD CONSTRAINT reauthentication_consumption_complete CHECK (
  (consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL)
  OR (consumed_command_id IS NOT NULL AND octet_length(consumed_command_id)=16
   AND consumed_purpose IS NOT NULL AND consumed_purpose IN (
    'identity.password.change','identity.mfa.enable','identity.email.verification-send',
    'identity.email.change-request','identity.email.address-remove',
    'identity.username.update','identity.organization.owner-transfer',
    'identity.phone.send-verification','identity.phone.remove','identity.phone.update',
    'identity.organization.archive','identity.organization.restore',
    'identity.anonymous.upgrade',
    'identity.passkey.register-options','identity.passkey.register-verify',
    'identity.passkey.update','identity.passkey.delete')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
