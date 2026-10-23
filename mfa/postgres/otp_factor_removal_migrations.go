package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OTPFactorRemovalMigrationSource appends explicit removal/recovery disposition
// to installed OTP management history. Existing effects remain renames; no
// recipient, credential, proof or installed migration bytes change. Select
// email recovery and install this forward history before accepting removals.
type OTPFactorRemovalMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves the installed prefix and appends one owned forward-only step.
// Missing/cancelled context, nil Base and conflicting versions fail closed.
func (s OTPFactorRemovalMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_mfa_otp_factor_removal", migrations.TransactionModeDefault, otpFactorRemovalSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = step
	return history, nil
}

const otpFactorRemovalSQL = `ALTER TABLE identity_mfa.otp_factor_update_effects
 ADD COLUMN action smallint NOT NULL DEFAULT 1 CHECK(action IN(1,2)),
 ADD COLUMN recovery_identity bytea,
 ADD CONSTRAINT otp_factor_update_recovery_identity_check CHECK(
 (action=1 AND recovery_identity IS NULL) OR
 (action=2 AND recovery_identity IS NOT NULL AND octet_length(recovery_identity)=32));`
