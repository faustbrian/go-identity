package mfapostgres

import (
	"context"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// OTPSendMigrationSource appends current-send attribution to existing pending
// factors. Prior OTP/TOTP histories remain byte-identical. No code, destination,
// challenge digest or attempt state is copied from OTP's owning schema.
// Install after OTPFactorMigrationSource; startup does not run migrations.
type OTPSendMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns the forward-only owned migration without IO. Version must be
// permanently allocated after the selected OTP-factor history.
func (s OTPSendMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_otp_send", migrations.TransactionModeDefault, otpSendSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

const otpSendSQL = `ALTER TABLE identity_mfa.otp_factors
 ADD COLUMN last_send_command_id bytea CHECK(octet_length(last_send_command_id)=16),
 ADD COLUMN last_send_before_version identity.version,
 ADD COLUMN last_send_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.mfa.otp-send' CHECK(last_send_purpose='identity.mfa.otp-send'),
 ADD CONSTRAINT mfa_otp_send_attribution CHECK(num_nonnulls(last_send_command_id,last_send_before_version) IN(0,2)),
 ADD CONSTRAINT mfa_otp_send_command FOREIGN KEY(tenant_id,last_send_purpose,last_send_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id);
CREATE UNIQUE INDEX mfa_otp_send_command_unique ON identity_mfa.otp_factors(tenant_id,last_send_command_id) WHERE last_send_command_id IS NOT NULL;
`
