package passwordpostgres

import (
	"context"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhoneChangeReauthenticationMigrationSource appends phone-update consumption
// to the existing password proof marker. Base includes installed action/phone
// histories and any selected removal suffix; Version follows every predecessor.
// Prior checksums, records, command foreign key and unique consuming-command
// index are preserved. Installing this history alone enables no workflow.
type PhoneChangeReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load copies a forward-only history without IO. Missing phone history, invalid
// ordering, nil or cancelled context fails without returning a partial history.
func (s PhoneChangeReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (ActionReauthenticationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	predecessor := false
	for _, step := range history[:len(history)-1] {
		predecessor = predecessor || step.Name() == "identity_password_phone_reauthentication_consumption"
	}
	if !predecessor {
		return nil, password.ErrPasswordWork
	}
	step, err := migrations.NewMigration(s.Version, "identity_password_phone_change_reauthentication_consumption", migrations.TransactionModeDefault, phoneChangeReauthenticationSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	history[len(history)-1] = step
	return history, nil
}

// Extend only the original marker's action allowlist. Its all-or-none shape,
// command foreign key and unique consumer still enforce same-transaction use;
// a separately committed or automatically consumed proof is not introduced.
const phoneChangeReauthenticationSQL = `ALTER TABLE identity_password.reauthentication_records
 DROP CONSTRAINT reauthentication_consumption_complete,
 ADD CONSTRAINT reauthentication_consumption_complete CHECK (
  (consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL)
  OR (consumed_command_id IS NOT NULL AND octet_length(consumed_command_id)=16
   AND consumed_purpose IS NOT NULL AND consumed_purpose IN (
    'identity.password.change','identity.mfa.enable','identity.email.verification-send',
    'identity.email.change-request','identity.email.address-remove',
    'identity.username.update','identity.organization.owner-transfer',
    'identity.phone.send-verification','identity.phone.remove','identity.phone.update')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
