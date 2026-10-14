package postgres

import (
	"context"
	"strings"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFAFactorUpdateSessionMigrationSource extends the existing native disposition
// table's closed purpose set for separately selected factor-update Work. The
// original whole-session effects history must already be installed. Existing
// evidence bytes and populated session records remain unchanged.
type MFAFactorUpdateSessionMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only transactional extension without IO. The same
// schema/version/context validation as the original native history applies.
// This source is not a replacement bootstrap and grants no session authority.
func (s MFAFactorUpdateSessionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if _, err := (MFARecoverySessionMigrationSource{Schema: s.Schema, Version: s.Version}).Load(ctx); err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_mfa_factor_update_session_effects", migrations.TransactionModeDefault, strings.ReplaceAll(factorUpdateSessionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{step}, nil
}

const factorUpdateSessionSQL = `ALTER TABLE @schema@.mfa_recovery_dispositions
 DROP CONSTRAINT mfa_recovery_dispositions_purpose_check,
 ADD CONSTRAINT mfa_recovery_dispositions_purpose_check
 CHECK(purpose IN('identity.mfa.recovery-regenerate','identity.mfa.factor-update'));`
