package postgres

import (
	"context"
	"math"
	"strings"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// AnonymousUpgradeMigrationSource appends guest revocation/permanent issuance
// purposes to already installed anonymous signin and disposal histories.
// AnonymousSignin describes that installed profile, including optional purpose
// extensions; it is not executed again. Version must be permanently allocated
// after both installed histories. No existing rows, SQL or digest domains change.
type AnonymousUpgradeMigrationSource struct {
	AnonymousSignin AnonymousSigninMigrationSource
	Version         migrations.Version
}

// Load returns only the transactional forward suffix without IO. A mismatched
// installed constraint fails rather than silently adopting another history.
// Install this suffix last among selected issuance-purpose extensions. No
// destructive downgrade, alternate replay store or cleanup is provided.
func (s AnonymousUpgradeMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if s.Version <= s.AnonymousSignin.Version || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "session_anonymous_upgrade_migration"}
	}
	if _, err := s.AnonymousSignin.Load(ctx); err != nil {
		return nil, err
	}
	_, purposes := anonymousIssuanceHistory(s.AnonymousSignin)
	sql := strings.NewReplacer("@schema@", pgx.Identifier{s.AnonymousSignin.Schema}.Sanitize(), "@purposes@", purposes).Replace(`ALTER TABLE @schema@.anonymous_disposals DROP CONSTRAINT anonymous_disposals_purpose_check;
ALTER TABLE @schema@.anonymous_disposals ADD CONSTRAINT anonymous_disposals_purpose_upgrade_v1 CHECK(purpose IN('identity.anonymous.delete','identity.anonymous.upgrade'));
ALTER TABLE @schema@.session_issuances DROP CONSTRAINT session_issuances_purpose_anonymous_v1;
ALTER TABLE @schema@.session_issuances ADD CONSTRAINT session_issuances_purpose_anonymous_upgrade_v1 CHECK(purpose IN(@purposes@,'identity.anonymous.upgrade'));
`)
	step, err := migrations.NewMigration(s.Version, "identity_session_anonymous_upgrade", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{step}, nil
}
