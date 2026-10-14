package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// FactorManagementMigrationSource appends safe presentation metadata and
// retained mutation effects after the existing factor-verification history.
// It preserves cryptographic and command bytes and does not enroll, reactivate
// or fabricate factors. Allocate Version permanently in the same namespace.
type FactorManagementMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves the exact populated prefix and returns forward-only SQL.
// Nil/canceled context, missing Base or conflicting versions deny without IO.
func (s FactorManagementMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_factor_management", migrations.TransactionModeDefault, factorManagementSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

const factorManagementSQL = `ALTER TABLE identity_mfa.totp_factors
 ADD COLUMN label text NOT NULL DEFAULT '' CHECK(octet_length(label)<=128 AND label !~ '[[:cntrl:]]');
ALTER TABLE identity_mfa.factor_verifications
 DROP CONSTRAINT factor_verifications_used_purpose_check,
 ADD CONSTRAINT factor_verifications_used_purpose_check
 CHECK(used_purpose IN('identity.mfa.recovery-regenerate','identity.mfa.factor-update'));
CREATE TABLE identity_mfa.factor_update_effects(
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.mfa.factor-update'),
 factor_id text COLLATE "C" NOT NULL,
 before_version identity.version NOT NULL CHECK(before_version<18446744073709551615),
 after_version identity.version NOT NULL CHECK(after_version=before_version+1),
 before_authority identity.version NOT NULL CHECK(before_authority<18446744073709551615),
 after_authority identity.version NOT NULL CHECK(after_authority=before_authority+1),
 proof_id text COLLATE "C" NOT NULL REFERENCES identity_mfa.factor_verifications(proof_id),
 PRIMARY KEY(tenant_id,command_id),
 FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES identity_mfa.totp_factors(tenant_id,user_id,factor_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id)
);`
