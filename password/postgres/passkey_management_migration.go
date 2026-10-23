package passwordpostgres

import (
	"context"

	"github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PasskeyManagementReauthenticationMigrationSource appends exact credential-label
// update consumption to the password-owned one-use marker. Base must include
// PasskeyReauthenticationMigrationSource and every installed selected suffix;
// Version follows them all. Existing migrations, signed records, command foreign
// keys and unique consumption identity remain unchanged. This selects neither
// credential deletion nor a native management workflow.
type PasskeyManagementReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns a copied forward-only history without IO. Missing enrollment
// history, invalid versions, predecessor errors and nil/canceled contexts return
// no partial history. No destructive rollback is offered.
func (s PasskeyManagementReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (PasskeyReauthenticationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	predecessor := false
	for _, step := range history[:len(history)-1] {
		predecessor = predecessor || step.Name() == "identity_password_passkey_reauthentication_consumption"
	}
	if !predecessor {
		return nil, password.ErrPasswordWork
	}
	step, err := migrations.NewMigration(s.Version, "identity_password_passkey_management_reauthentication_consumption", migrations.TransactionModeDefault, passkeyManagementReauthenticationSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	history[len(history)-1] = step
	return history, nil
}

// Enrollment's installed SQL remains immutable. Extend its closed marker only
// for the exact rename proof; the protected owner still authenticates current
// custody and consumes once inside the same transaction as its metadata effect.
const passkeyManagementReauthenticationSQL = `ALTER TABLE identity_password.reauthentication_records
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
    'identity.passkey.update')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
