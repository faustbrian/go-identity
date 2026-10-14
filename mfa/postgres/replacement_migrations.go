package mfapostgres

import (
	"context"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// TOTPReplacementMigrationSource appends explicit predecessor/successor
// provenance and pending-initiation effects. Install after management/removal
// metadata; disable is independently optional. Old migration SQL is unchanged.
type TOTPReplacementMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves populated history and appends only the forward replacement
// schema. No downgrade, generated authority or installed receipt rewriting.
func (s TOTPReplacementMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_mfa_totp_replacement", migrations.TransactionModeDefault, totpReplacementSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = step
	return history, nil
}

const totpReplacementSQL = `ALTER TABLE identity_mfa.totp_factors
 ADD COLUMN replaces_factor_id text COLLATE "C",
 ADD COLUMN replaces_version identity.version,
 ADD CONSTRAINT totp_replacement_binding CHECK(num_nonnulls(replaces_factor_id,replaces_version) IN(0,2) AND (replaces_factor_id IS NULL OR (created_purpose='identity.mfa.factor-update' AND replaces_factor_id<>factor_id))),
 ADD CONSTRAINT totp_replacement_predecessor FOREIGN KEY(tenant_id,user_id,replaces_factor_id) REFERENCES identity_mfa.totp_factors(tenant_id,user_id,factor_id);
CREATE UNIQUE INDEX totp_one_pending_replacement ON identity_mfa.totp_factors(tenant_id,user_id,replaces_factor_id) WHERE state=1 AND replaces_factor_id IS NOT NULL;
ALTER TABLE identity_mfa.recovery_sets
 DROP CONSTRAINT recovery_sets_created_purpose_check,
 ADD CONSTRAINT recovery_sets_created_purpose_check CHECK(created_purpose IN('identity.mfa.enable','identity.mfa.recovery-regenerate','identity.mfa.factor-update'));
ALTER TABLE identity_mfa.factor_update_effects
 DROP CONSTRAINT factor_update_effects_action_check,
 DROP CONSTRAINT factor_update_recovery_identity_check,
 DROP CONSTRAINT factor_update_effects_check1,
 ADD COLUMN replacement_factor_id text COLLATE "C",
 ADD CONSTRAINT factor_update_effects_action_check CHECK(action IN(1,2,3)),
 ADD CONSTRAINT factor_update_recovery_identity_check CHECK((action IN(1,3) AND recovery_identity IS NULL) OR (action=2 AND recovery_identity IS NOT NULL AND octet_length(recovery_identity)=32)),
 ADD CONSTRAINT factor_update_effects_after_authority_check CHECK((action IN(1,2) AND after_authority=before_authority+1) OR (action=3 AND after_authority=before_authority)),
 ADD CONSTRAINT factor_update_replacement_target CHECK((action=3 AND purpose='identity.mfa.factor-update' AND replacement_factor_id IS NOT NULL AND replacement_factor_id<>factor_id) OR (action IN(1,2) AND replacement_factor_id IS NULL)),
 ADD CONSTRAINT factor_update_replacement_factor FOREIGN KEY(tenant_id,user_id,replacement_factor_id) REFERENCES identity_mfa.totp_factors(tenant_id,user_id,factor_id);
`
