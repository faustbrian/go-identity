package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// IdentifierRemovalCascadeMigrationSource extends the existing identity-owned
// cascade admission tables, not a second lifecycle journal. Base must contain
// StatusMigrationSource and Version must follow all base history. Existing status
// policy, rows, pending consumers and authority dimensions are unchanged. This
// migration admits identifier removal; consumer acknowledgement/closure is separate.
type IdentifierRemovalCascadeMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns owned forward-only history without IO or destructive rollback.
// Missing prerequisite, invalid ordering and cancellation fail closed.
func (s IdentifierRemovalCascadeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "identifier_cascade_migration"}
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
	status := false
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalid
		}
		status = status || m.Name() == "identity_status_admission"
	}
	if !status {
		return nil, invalid
	}
	forward, err := migrations.NewMigration(s.Version, "identity_identifier_removal_cascade", migrations.TransactionModeDefault, identifierRemovalCascadeSchemaSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const identifierRemovalCascadeSchemaSQL = `ALTER TABLE identity.status_cascades
 ADD COLUMN cascade_kind text COLLATE "C" NOT NULL DEFAULT 'status',
 ADD COLUMN authority_dimension text COLLATE "C" NOT NULL DEFAULT 'user',
 ADD COLUMN identifier_id identity.directory_id,
 DROP CONSTRAINT status_cascades_trigger_event_type_check,
 ADD CONSTRAINT status_cascades_trigger_event_type_check CHECK
  (trigger_event_type IN ('identity.suspended.v1','identity.restored.v1','identifier.removed.v1')),
 ADD CONSTRAINT identity_cascade_scope CHECK (
  (cascade_kind='status' AND authority_dimension='user' AND identifier_id IS NULL
   AND trigger_event_type IN ('identity.suspended.v1','identity.restored.v1')) OR
  (cascade_kind='lifecycle.cascade.identifier_remove' AND authority_dimension='identifier'
   AND identifier_id IS NOT NULL AND operation='identity.email.address-remove'
   AND trigger_event_type='identifier.removed.v1'));
`
