package postgres

import (
	"context"
	"strings"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFADisableSessionMigrationSource appends the exact disable disposition purpose
// without changing installed regeneration/update SQL or retained result bytes.
type MFADisableSessionMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only transactional extension without IO. Base
// disposition and factor-update extensions must already be installed.
func (s MFADisableSessionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if _, err := (MFARecoverySessionMigrationSource{Schema: s.Schema, Version: s.Version}).Load(ctx); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_mfa_disable_session_effects", migrations.TransactionModeDefault, strings.ReplaceAll(disableSessionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{m}, nil
}

const disableSessionSQL = `ALTER TABLE @schema@.mfa_recovery_dispositions
 DROP CONSTRAINT mfa_recovery_dispositions_purpose_check,
 ADD CONSTRAINT mfa_recovery_dispositions_purpose_check
 CHECK(purpose IN('identity.mfa.recovery-regenerate','identity.mfa.factor-update','identity.mfa.disable'));`
