package passwordpostgres

import (
	"context"
	"math"
	"reflect"

	"github.com/faustbrian/go-identity/password"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// AccountUnlinkReauthenticationMigrationSource allows a typed unlink command
// to consume the existing password proof. Base must contain the complete
// installed password history and any other selected consumption suffixes.
// Three steps extend the existing proof row, build its bounded partial unique
// index, and validate the new constraints. Older optional action
// migrations still own their original consumption allowlist; this migration
// neither installs nor changes it. Install all steps before enabling unlink.
type AccountUnlinkReauthenticationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns a copied forward-only history. Invalid or missing predecessor
// configuration and cancellation return no partial result.
func (s AccountUnlinkReauthenticationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Base == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64-2) {
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
	predecessor := false
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, password.ErrPasswordWork
		}
		predecessor = predecessor || step.Name() == "identity_password_reauthentication_consumption"
	}
	if !predecessor {
		return nil, password.ErrPasswordWork
	}
	expand, err := migrations.NewMigration(s.Version, "identity_password_unlink_consumption_expand", migrations.TransactionModeDefault, unlinkConsumptionExpandSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	index, err := migrations.NewMigration(s.Version+1, "identity_password_unlink_consumption_index", migrations.TransactionModeDefault, unlinkConsumptionIndexSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	validate, err := migrations.NewMigration(s.Version+2, "identity_password_unlink_consumption_validate", migrations.TransactionModeDefault, unlinkConsumptionValidateSQL, "")
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append(append([]migrations.Migration(nil), history...), expand, index, validate), nil
}

// Nullable columns need no backfill. Cross-marker exclusivity keeps a single
// one-use boundary on the same proof row even for earlier password writers.
const unlinkConsumptionExpandSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE identity_password.reauthentication_records
 ADD COLUMN unlink_consumed_command_id bytea,
 ADD COLUMN unlink_consumed_purpose text COLLATE "C",
 ADD COLUMN unlink_consumed_at timestamptz,
 ADD CONSTRAINT reauthentication_unlink_consumption_complete CHECK (
  (unlink_consumed_command_id IS NULL AND unlink_consumed_purpose IS NULL AND unlink_consumed_at IS NULL)
  OR (consumed_command_id IS NULL
   AND unlink_consumed_command_id IS NOT NULL AND octet_length(unlink_consumed_command_id)=16
   AND unlink_consumed_purpose IS NOT NULL AND unlink_consumed_purpose='identity.account.unlink'
   AND unlink_consumed_at IS NOT NULL AND isfinite(unlink_consumed_at)
   AND unlink_consumed_at>='0001-01-01 00:00:00+00'::timestamptz
   AND unlink_consumed_at<'10000-01-01 00:00:00+00'::timestamptz)) NOT VALID,
 ADD CONSTRAINT reauthentication_unlink_consumption_command
 FOREIGN KEY(tenant_id,unlink_consumed_purpose,unlink_consumed_command_id)
 REFERENCES identity.commands(tenant_id,purpose,command_id) NOT VALID;
`

// Reference applies each recorded step transactionally, so this cannot be a
// concurrent index build. Bound both its wait and write-blocking interval;
// failure rolls back only this step and the recorded expansion stays resumable.
const unlinkConsumptionIndexSQL = `SET LOCAL lock_timeout='250ms';
SET LOCAL statement_timeout='2s';
CREATE UNIQUE INDEX reauthentication_unlink_consumption_once
ON identity_password.reauthentication_records(tenant_id,unlink_consumed_purpose,unlink_consumed_command_id)
WHERE unlink_consumed_command_id IS NOT NULL;`

const unlinkConsumptionValidateSQL = `SET LOCAL lock_timeout='5s';
ALTER TABLE identity_password.reauthentication_records
 VALIDATE CONSTRAINT reauthentication_unlink_consumption_complete,
 VALIDATE CONSTRAINT reauthentication_unlink_consumption_command;
`
