package passwordpostgres

import (
	"context"

	"github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// AnonymousUpgradeReauthenticationMigrationSource appends upgrade consumption to
// the existing password-owned one-use marker. Base must contain action proof
// history and every selected email, phone and organization suffix; install this
// source last. Existing signed records, checksums, command foreign keys and
// unique consumption identity are unchanged. Installation enables no workflow.
type AnonymousUpgradeReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns a forward-only history without IO. Missing action history,
// invalid versions, nil/canceled context and predecessor failure deny without
// returning a partial history. No destructive rollback is offered.
func (s AnonymousUpgradeReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	step, err := migrations.NewMigration(s.Version, "identity_password_anonymous_upgrade_reauthentication_consumption", migrations.TransactionModeDefault, anonymousUpgradeReauthenticationSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	history[len(history)-1] = step
	return history, nil
}

// Extend the existing complete marker rather than creating a parallel proof
// ledger. The source remains the permanent target's exact signed password
// record; the anonymous owner must separately prove guest possession and fence
// both identities before consuming this record in the same protected Work.
const anonymousUpgradeReauthenticationSQL = `ALTER TABLE identity_password.reauthentication_records
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
    'identity.anonymous.upgrade')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
