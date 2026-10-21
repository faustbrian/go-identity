package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// AnonymousDisposalMigrationSource appends retained, payload-free kernel
// disposal evidence after anonymous creation and legal-hold histories. Existing
// populated predecessor SQL is returned unchanged; Version follows every installed
// successor. This enables no workflow and offers no destructive downgrade.
type AnonymousDisposalMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load validates the complete selected history without IO. The existing runner
// owns installation; missing prerequisites, invalid order and cancellation deny.
func (s AnonymousDisposalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	invalid := identity.InvalidInputError{Field: "anonymous_disposal_migration"}
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
	creation, hold := false, false
	for _, m := range history {
		if m.Version() >= s.Version {
			return nil, invalid
		}
		creation = creation || m.Name() == "identity_anonymous_placeholder"
		hold = hold || m.Name() == "identity_status_admission"
	}
	if !creation || !hold {
		return nil, invalid
	}
	m, err := migrations.NewMigration(s.Version, "identity_anonymous_disposals", migrations.TransactionModeDefault, anonymousDisposalSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), m), nil
}

const anonymousDisposalSQL = `CREATE TABLE identity.anonymous_disposals(
 tenant_id identity.directory_id NOT NULL,
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.anonymous.delete'),
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 user_id identity.directory_id NOT NULL,
 action text COLLATE "C" NOT NULL CHECK(action IN ('delete','anonymize','retain')),
 before_version identity.version NOT NULL,
 after_version identity.version NOT NULL CHECK(after_version=before_version+1),
 before_user_version identity.version NOT NULL,
 before_authority_version identity.version NOT NULL,
 before_identifier_version identity.version NOT NULL,
 before_credential_version identity.version NOT NULL,
 legal_hold boolean NOT NULL,
 legal_hold_version identity.version NOT NULL,
 retention_policy_version identity.version NOT NULL,
 PRIMARY KEY(tenant_id,purpose,command_id),
 UNIQUE(tenant_id,user_id),
 CHECK(NOT legal_hold OR action='retain'),
 FOREIGN KEY(tenant_id,user_id) REFERENCES identity.users(tenant_id,user_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);
`
