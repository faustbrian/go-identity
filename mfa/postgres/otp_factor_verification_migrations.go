package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OTPFactorVerificationMigrationSource appends original signed active-OTP
// action evidence after the selected OTP factor and kernel histories. It does
// not alter existing TOTP proofs, issue a challenge or enable a workflow.
// Version must follow Base permanently; rollback is unsupported. Construction
// and Load perform no IO. Actual application fails if required owners are absent.
type OTPFactorVerificationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves all predecessor bytes and appends one owned forward migration.
// Missing/canceled context, nil Base and conflicting versions fail closed.
func (s OTPFactorVerificationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_otp_factor_verifications", migrations.TransactionModeDefault, otpFactorVerificationSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

// OTP proofs retain their actual factor foreign key. Reusing the TOTP table
// would either forge a TOTP predecessor or weaken its existing foreign key.
// The sole coordinator journal and signed authentication format are unchanged.
const otpFactorVerificationSQL = `CREATE TABLE identity_mfa.otp_factor_verifications (
 proof_id text COLLATE "C" PRIMARY KEY CHECK(proof_id ~ '^[A-Za-z0-9_-]{22}$'),
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 factor_id text COLLATE "C" NOT NULL,
 enrollment_version identity.version NOT NULL,
 factor_authority_version identity.version NOT NULL,
 command_id bytea NOT NULL CHECK(octet_length(command_id)=16),
 purpose text COLLATE "C" NOT NULL CHECK(purpose='identity.mfa.otp-verify'),
 record bytea NOT NULL CHECK(octet_length(record) BETWEEN 1 AND 32768),
 used_command_id bytea CHECK(octet_length(used_command_id)=16),
 used_purpose text COLLATE "C" CHECK(used_purpose='identity.mfa.factor-update'),
 used_at timestamptz CHECK(isfinite(used_at)),
 UNIQUE(tenant_id,purpose,command_id),
 FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES identity_mfa.otp_factors(tenant_id,user_id,factor_id),
 FOREIGN KEY(tenant_id,purpose,command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 FOREIGN KEY(tenant_id,used_purpose,used_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK(proof_id=translate(rtrim(encode(command_id,'base64'),'='),'+/','-_')),
 CHECK(num_nonnulls(used_command_id,used_purpose,used_at) IN(0,3))
);
CREATE INDEX mfa_otp_factor_verification_subject ON identity_mfa.otp_factor_verifications(tenant_id,user_id,proof_id);
`
