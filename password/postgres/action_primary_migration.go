package passwordpostgres

import (
	"context"
	"math"
	"reflect"

	password "github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// ActionReauthenticationMigrationSource appends consumption support for the two
// selected native action profiles. Base must contain the complete installed
// password history; Version follows every predecessor, including any selected
// email/username suffix. Existing checksums, records, one-use uniqueness and
// command foreign keys are unchanged. Installation enables no workflow itself.
type ActionReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns a copied forward-only history without IO or destructive SQL.
func (s ActionReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, password.ErrPasswordWork
	}
	base := reflect.ValueOf(s.Base)
	switch base.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if base.IsNil() {
			return nil, password.ErrPasswordWork
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, password.ErrPasswordWork
	}
	for _, previous := range history {
		if previous.Version() >= s.Version {
			return nil, password.ErrPasswordWork
		}
	}
	addition, err := migrations.NewMigration(s.Version, "identity_password_action_reauthentication_consumption", migrations.TransactionModeDefault, actionReauthenticationConsumptionSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	return append(append([]migrations.Migration(nil), history...), addition), nil
}

// Extend only the original one-use marker's closed operation allowlist. The
// existing command foreign key/unique index keep proof use in the protected
// coordinator transaction; there is no separate action-use ledger.
const actionReauthenticationConsumptionSQL = `ALTER TABLE identity_password.reauthentication_records
 DROP CONSTRAINT reauthentication_consumption_complete,
 ADD CONSTRAINT reauthentication_consumption_complete CHECK (
  (consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL)
  OR (consumed_command_id IS NOT NULL AND octet_length(consumed_command_id)=16
   AND consumed_purpose IS NOT NULL AND consumed_purpose IN (
    'identity.password.change','identity.mfa.enable','identity.email.verification-send',
    'identity.email.change-request','identity.email.address-remove',
    'identity.username.update','identity.organization.owner-transfer')
   AND consumed_at IS NOT NULL AND isfinite(consumed_at)
   AND consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND consumed_at<'10000-01-01 00:00:00+00'::timestamptz));
`
