package mfapostgres

import (
	"context"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// DisableMigrationSource appends distinct disable-purpose proof use and retained
// explicit target scope after removal history. Existing receipt bytes stay valid.
type DisableMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves the exact prefix and returns only forward migration semantics.
func (s DisableMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_mfa_disable", migrations.TransactionModeDefault, disableSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = step
	return history, nil
}

const disableSQL = `ALTER TABLE identity_mfa.factor_verifications
 DROP CONSTRAINT factor_verifications_used_purpose_check,
 ADD CONSTRAINT factor_verifications_used_purpose_check
 CHECK(used_purpose IN('identity.mfa.recovery-regenerate','identity.mfa.factor-update','identity.mfa.disable'));
ALTER TABLE identity_mfa.factor_update_effects
 DROP CONSTRAINT factor_update_effects_purpose_check,
 ADD CONSTRAINT factor_update_effects_purpose_check
 CHECK(purpose IN('identity.mfa.factor-update','identity.mfa.disable')),
 ADD COLUMN disable_target smallint,
 ADD CONSTRAINT factor_update_disable_target_check CHECK(
 (purpose='identity.mfa.factor-update' AND disable_target IS NULL) OR
 (purpose='identity.mfa.disable' AND disable_target IS NOT NULL AND disable_target IN(1,2)));
`
