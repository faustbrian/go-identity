package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhoneChangeCascadeMigrationSource extends the existing cascade tables for
// atomic verified-phone replacement. Base must retain the phone-removal and
// identifier-removal predecessors and Version must follow all installed history.
// Apply this forward-only migration before selecting replacement; it creates no
// journal, acknowledgement authority or active workflow by itself.
type PhoneChangeCascadeMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load copies history and appends bounded constraint changes without IO.
func (s PhoneChangeCascadeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "phone_change_cascade_migration"}
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, invalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	removal := false
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, invalid
		}
		removal = removal || step.Name() == "identity_phone_removal_cascade"
	}
	if !removal {
		return nil, invalid
	}
	step, err := migrations.NewMigration(s.Version, "identity_phone_change_cascade", migrations.TransactionModeDefault, phoneChangeCascadeSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), step), nil
}

const phoneChangeCascadeSQL = `ALTER TABLE identity.status_cascades
 DROP CONSTRAINT status_cascades_trigger_event_type_check,
 ADD CONSTRAINT status_cascades_trigger_event_type_check CHECK
  (trigger_event_type IN ('identity.suspended.v1','identity.restored.v1','identifier.removed.v1','identifier.changed.v1')),
 DROP CONSTRAINT identity_cascade_scope,
 ADD CONSTRAINT identity_cascade_scope CHECK (
  (cascade_kind='status' AND authority_dimension='user' AND identifier_id IS NULL
   AND trigger_event_type IN ('identity.suspended.v1','identity.restored.v1')) OR
  (cascade_kind='lifecycle.cascade.identifier_remove' AND authority_dimension='identifier'
   AND identifier_id IS NOT NULL
   AND operation IN ('identity.email.address-remove','identity.phone.remove')
   AND trigger_event_type='identifier.removed.v1') OR
  (cascade_kind='lifecycle.cascade.identifier_change' AND authority_dimension='identifier'
   AND identifier_id IS NOT NULL AND operation='identity.phone.update'
   AND trigger_event_type='identifier.changed.v1'));
`
