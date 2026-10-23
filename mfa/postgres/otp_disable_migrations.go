package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OTPDisableMigrationSource appends distinct disable-purpose proof use and
// explicit one/all disposition after OTP removal history. Installed prefix
// bytes, existing rename/removal receipts and TOTP history remain unchanged.
type OTPDisableMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends one forward-only step without IO. Missing/canceled context,
// absent Base and conflicting versions fail closed.
func (s OTPDisableMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_mfa_otp_disable", migrations.TransactionModeDefault, otpDisableSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = step
	return history, nil
}

const otpDisableSQL = `ALTER TABLE identity_mfa.otp_factor_verifications
 DROP CONSTRAINT otp_factor_verifications_used_purpose_check,
 ADD CONSTRAINT otp_factor_verifications_used_purpose_check
 CHECK(used_purpose IN('identity.mfa.factor-update','identity.mfa.disable'));
ALTER TABLE identity_mfa.otp_factor_update_effects
 DROP CONSTRAINT otp_factor_update_effects_purpose_check,
 ADD CONSTRAINT otp_factor_update_effects_purpose_check
 CHECK(purpose IN('identity.mfa.factor-update','identity.mfa.disable')),
 ADD COLUMN disable_target smallint,
 ADD CONSTRAINT otp_factor_update_disable_target_check CHECK(
 (purpose='identity.mfa.factor-update' AND disable_target IS NULL) OR
 (purpose='identity.mfa.disable' AND action=2 AND disable_target IS NOT NULL AND disable_target IN(1,2)));`
