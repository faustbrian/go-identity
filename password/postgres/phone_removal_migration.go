package passwordpostgres

import (
	"context"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhoneRemovalReauthenticationMigrationSource adds only phone removal to the
// existing password proof's one-use purposes. Base includes the installed action
// and phone-enrollment histories; Version follows every predecessor. Existing
// SQL/checksums, proof records, command foreign key and unique consuming command
// index are preserved. Installing this suffix enables no workflow by itself.
type PhoneRemovalReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns a copied forward-only successor without IO. Missing prerequisite,
// nil/cancelled context or invalid ordering denies without a partial history.
func (s PhoneRemovalReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	step, err := migrations.NewMigration(s.Version, "identity_password_phone_removal_reauthentication_consumption", migrations.TransactionModeDefault, phoneRemovalReauthenticationSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	history[len(history)-1] = step
	return history, nil
}

const phoneRemovalReauthenticationSQL = `ALTER TABLE identity_password.reauthentication_records
 DROP CONSTRAINT reauthentication_consumption_complete,
 ADD CONSTRAINT reauthentication_consumption_complete CHECK (
  (consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL)
  OR (consumed_command_id IS NOT NULL AND octet_length(consumed_command_id)=16
   AND consumed_purpose IS NOT NULL AND consumed_purpose IN (
    'identity.password.change','identity.mfa.enable','identity.email.verification-send',
    'identity.email.change-request','identity.email.address-remove',
    'identity.username.update','identity.organization.owner-transfer',
    'identity.phone.send-verification','identity.phone.remove')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
