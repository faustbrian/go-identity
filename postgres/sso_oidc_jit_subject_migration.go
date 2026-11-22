package postgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// SSOOIDCSubjectAvailabilityMigrationSource appends a non-unique retired
// provider-subject digest index to Base, which must include AccountMigrationSource.
// Version must follow all selected history. Apply this before enabling native
// SSO OIDC JIT; no existing account, credential, social-link rule or migration
// byte changes. No provisioning or authentication authority is created.
//
// The one concurrent index statement runs outside a transaction, under the
// caller's bounded migration Runner context. It permits ordinary reads/writes
// but can wait for older transactions and consumes build I/O/storage. A failed
// build requires inspecting pg_index.indisvalid and explicit migration recovery;
// drop an invalid index concurrently before retrying rather than accepting its
// name as proof of completion. Reverting code can leave this additive index in
// place; no destructive down migration is provided.
type SSOOIDCSubjectAvailabilityMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

var _ migrations.Source = SSOOIDCSubjectAvailabilityMigrationSource{}

// Load returns independent forward-only history without performing I/O.
// Invalid composition and cancellation return no partial history.
func (s SSOOIDCSubjectAvailabilityMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || nilStatusSource(s.Base) || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "sso_oidc_subject_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	history, err := s.Base.Load(ctx)
	if err != nil {
		return nil, err
	}
	if len(history) == 0 {
		return nil, identity.InvalidInputError{Field: "sso_oidc_subject_migration"}
	}
	for _, migration := range history {
		if migration.Version() >= s.Version {
			return nil, identity.InvalidInputError{Field: "sso_oidc_subject_migration"}
		}
	}
	forward, err := migrations.NewMigration(s.Version, "identity_sso_oidc_retired_subject", migrations.TransactionModeNone, ssoOIDCSubjectAvailabilityIndexSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return append(append([]migrations.Migration(nil), history...), forward), nil
}

const ssoOIDCSubjectAvailabilityIndexSQL = `CREATE INDEX CONCURRENTLY identity_accounts_retired_subject ON identity.accounts(tenant_id,subject_key) WHERE NOT linked;`
