package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OTPFactorManagementMigrationSource appends OTP presentation metadata and
// original mutation effects after its OTP proof history. Existing TOTP and OTP
// credential/recipient bytes remain unchanged. It enables no management route
// or permission. Version is permanently allocated; rollback is unsupported.
type OTPFactorManagementMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load appends owned SQL without IO, preserving the exact installed prefix.
// Missing/canceled context, nil Base and conflicting versions fail closed.
func (s OTPFactorManagementMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_otp_factor_management", migrations.TransactionModeDefault, otpFactorManagementSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

const otpFactorManagementSQL = `ALTER TABLE identity_mfa.otp_factors
 ADD COLUMN label text NOT NULL DEFAULT '' CHECK(octet_length(label)<=128 AND label !~ '[[:cntrl:]]');
CREATE TABLE identity_mfa.otp_factor_update_effects(
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.mfa.factor-update'),
 factor_id text COLLATE "C" NOT NULL,
 before_version identity.version NOT NULL CHECK(before_version<18446744073709551615),
 after_version identity.version NOT NULL CHECK(after_version=before_version+1),
 before_authority identity.version NOT NULL CHECK(before_authority<18446744073709551615),
 after_authority identity.version NOT NULL CHECK(after_authority=before_authority+1),
 proof_id text COLLATE "C" NOT NULL REFERENCES identity_mfa.otp_factor_verifications(proof_id),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES identity_mfa.otp_factors(tenant_id,user_id,factor_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);`
