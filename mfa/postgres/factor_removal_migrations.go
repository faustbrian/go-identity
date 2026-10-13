package mfapostgres

import (
	"context"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// FactorRemovalMigrationSource appends removal disposition metadata without
// rewriting installed management history or treating old renames as removals.
// Version belongs to the shared MFA namespace; no downgrade is supplied.
type FactorRemovalMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns the exact installed prefix plus the explicit forward suffix.
func (s FactorRemovalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_mfa_factor_removal", migrations.TransactionModeDefault, factorRemovalSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = step
	return history, nil
}

const factorRemovalSQL = `ALTER TABLE identity_mfa.factor_update_effects
 ADD COLUMN action smallint NOT NULL DEFAULT 1 CHECK(action IN(1,2)),
 ADD COLUMN recovery_identity bytea,
 ADD CONSTRAINT factor_update_recovery_identity_check CHECK(
 (action=1 AND recovery_identity IS NULL) OR
 (action=2 AND recovery_identity IS NOT NULL AND octet_length(recovery_identity)=32));`
