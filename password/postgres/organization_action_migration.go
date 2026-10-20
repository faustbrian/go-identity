package passwordpostgres

import (
	"context"

	"github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// OrganizationLifecycleReauthenticationMigrationSource appends archive/restore
// consumption to the existing password-owned one-use marker. Base must include
// ActionReauthenticationMigrationSource and every selected phone/email suffix;
// install this source last. Predecessor bytes, retained signed records, command
// foreign keys and unique consumer index remain unchanged. No workflow is enabled.
type OrganizationLifecycleReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns the forward history without IO. Missing action history, invalid
// ordering or canceled/nil context fails without returning a partial history.
func (s OrganizationLifecycleReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
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
	step, err := migrations.NewMigration(s.Version, "identity_password_organization_lifecycle_reauthentication_consumption", migrations.TransactionModeDefault, organizationLifecycleReauthenticationSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	history[len(history)-1] = step
	return history, nil
}

// Preserve every preceding selected purpose. The protected owner still requires
// an authentic exact-action proof and current session, and consumes in the sole
// coordinator Work; this allowlist does not grant authority by itself.
const organizationLifecycleReauthenticationSQL = `ALTER TABLE identity_password.reauthentication_records
 DROP CONSTRAINT reauthentication_consumption_complete,
 ADD CONSTRAINT reauthentication_consumption_complete CHECK (
  (consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL)
  OR (consumed_command_id IS NOT NULL AND octet_length(consumed_command_id)=16
   AND consumed_purpose IS NOT NULL AND consumed_purpose IN (
    'identity.password.change','identity.mfa.enable','identity.email.verification-send',
    'identity.email.change-request','identity.email.address-remove',
    'identity.username.update','identity.organization.owner-transfer',
    'identity.phone.send-verification','identity.phone.remove','identity.phone.update',
    'identity.organization.archive','identity.organization.restore')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
