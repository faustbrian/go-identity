package passwordpostgres

import (
	"context"

	"github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PasskeyReauthenticationMigrationSource appends exact passkey enrollment
// consumption to the existing password-owned one-use marker. Base must include
// ActionReauthenticationMigrationSource and all selected email, phone,
// organization and anonymous suffixes; Version follows every predecessor.
// Existing signed records, checksums, command foreign keys and unique consuming
// command identity remain unchanged. Installation enables no passkey workflow.
type PasskeyReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns the copied forward-only history without IO. Missing original
// action history, invalid versions, nil/canceled context and predecessor errors
// return no partial history. No destructive rollback is offered.
func (s PasskeyReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (ActionReauthenticationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	predecessor := false
	for _, step := range history[:len(history)-1] {
		predecessor = predecessor || step.Name() == "identity_password_action_reauthentication_consumption"
	}
	if !predecessor {
		return nil, password.ErrPasswordWork
	}
	step, err := migrations.NewMigration(s.Version, "identity_password_passkey_reauthentication_consumption", migrations.TransactionModeDefault, passkeyReauthenticationSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	history[len(history)-1] = step
	return history, nil
}

// Preserve every preceding purpose and the original marker's all-or-none
// shape. Each distinct enrollment phase still needs its exact signed proof,
// atomically consumed with that protected command, never by Verify itself.
const passkeyReauthenticationSQL = `ALTER TABLE identity_password.reauthentication_records
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
    'identity.passkey.register-options','identity.passkey.register-verify')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
