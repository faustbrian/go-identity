package passwordpostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhoneReauthenticationMigrationSource appends initial phone enrollment to the
// existing password proof's one-use consumption constraint. Base must include
// ActionReauthenticationMigrationSource and every other installed predecessor;
// Version must follow them all. Installed migration bytes and retained proof
// records are unchanged. Apply the suffix before selecting phone enrollment.
// This enables no other phone action and creates no separate consumption store.
type PhoneReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load copies the selected history and appends the forward-only constraint
// extension without database access. Nil/cancelled context, empty or typed-nil
// Base, and an invalid or non-successor Version fail closed.
func (s PhoneReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (ActionReauthenticationMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_password_phone_reauthentication_consumption", migrations.TransactionModeDefault, phoneReauthenticationConsumptionSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

// Keep prior actions and the exact all-or-none marker shape. The existing
// command foreign key and unique consumer index still own atomic one-use proof
// consumption; only the new self-service enrollment purpose is admitted.
const phoneReauthenticationConsumptionSQL = `ALTER TABLE identity_password.reauthentication_records
 DROP CONSTRAINT reauthentication_consumption_complete,
 ADD CONSTRAINT reauthentication_consumption_complete CHECK (
  (consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL)
  OR (consumed_command_id IS NOT NULL AND octet_length(consumed_command_id)=16
   AND consumed_purpose IS NOT NULL AND consumed_purpose IN (
    'identity.password.change','identity.mfa.enable','identity.email.verification-send',
    'identity.email.change-request','identity.email.address-remove',
    'identity.username.update','identity.organization.owner-transfer',
    'identity.phone.send-verification')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
