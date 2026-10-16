package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// EmailChangeFactorMigrationSource appends email-request proof consumption to
// the existing MFA evidence owner. Prior history and used records are preserved;
// no proof, factor, authority or second journal is created or backfilled.
type EmailChangeFactorMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load validates the existing MFA source/version contract and appends only
// forward SQL. The selected base must already contain factor-verification DDL.
func (s EmailChangeFactorMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(s.Version, "identity_mfa_email_change_factor_use", migrations.TransactionModeDefault, emailChangeFactorSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = step
	return history, nil
}

const emailChangeFactorSQL = `ALTER TABLE identity_mfa.factor_verifications
 DROP CONSTRAINT factor_verifications_used_purpose_check,
 ADD CONSTRAINT factor_verifications_used_purpose_check
 CHECK(used_purpose IN('identity.mfa.recovery-regenerate','identity.mfa.factor-update','identity.mfa.disable','identity.email.change-request'));
`
