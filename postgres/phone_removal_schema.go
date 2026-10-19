package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// PhoneRemovalCascadeMigrationSource extends the existing identifier-removal
// cascade constraint to the exact phone removal operation. Base must include
// IdentifierRemovalCascadeMigrationSource and every installed predecessor;
// Version follows them all. Existing status/email rows, checksums, pending
// consumers and command ownership are preserved. No new journal is created.
type PhoneRemovalCascadeMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load copies the selected history and appends a forward-only constraint change.
// It does no IO and enables no workflow or cleanup acknowledgement by itself.
func (s PhoneRemovalCascadeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "phone_removal_cascade_migration"}
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
	predecessor := false
	for _, step := range history {
		if step.Version() >= s.Version {
			return nil, invalid
		}
		predecessor = predecessor || step.Name() == "identity_identifier_removal_cascade"
	}
	if !predecessor {
		return nil, invalid
	}
	step, err := migrations.NewMigration(s.Version, "identity_phone_removal_cascade", migrations.TransactionModeDefault, phoneRemovalCascadeSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), step), nil
}

const phoneRemovalCascadeSQL = `ALTER TABLE identity.status_cascades
 DROP CONSTRAINT identity_cascade_scope,
 ADD CONSTRAINT identity_cascade_scope CHECK (
  (cascade_kind='status' AND authority_dimension='user' AND identifier_id IS NULL
   AND trigger_event_type IN ('identity.suspended.v1','identity.restored.v1')) OR
  (cascade_kind='lifecycle.cascade.identifier_remove' AND authority_dimension='identifier'
   AND identifier_id IS NOT NULL
   AND operation IN ('identity.email.address-remove','identity.phone.remove')
   AND trigger_event_type='identifier.removed.v1'));
`
