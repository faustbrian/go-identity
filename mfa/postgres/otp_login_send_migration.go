package mfapostgres

import (
	"context"
	"math"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// OTPLoginSendMigrationSource appends the current OTP challenge reference to
// the existing MFA continuation. Allocate Version after the selected OTP-factor,
// send and password-continuation histories. It owns no code, digest, delivery,
// transaction journal or credential authority. Existing records retain NULL
// attribution: no original send may be inferred or backfilled for them.
type OTPLoginSendMigrationSource struct{ Version migrations.Version }

// Load returns one forward-only atomic migration without IO. Original scopes,
// versions, attempt budgets, times and terminal records remain unchanged.
func (s OTPLoginSendMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if ctx == nil || s.Version == 0 || s.Version > migrations.Version(math.MaxInt64) {
		return nil, identity.InvalidInputError{Field: "mfa_otp_login_send_migration"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_mfa_otp_login_send", migrations.TransactionModeDefault, otpLoginSendSQL, "")
	if err != nil {
		return nil, identity.UnavailableError{}
	}
	return []migrations.Migration{m}, nil
}

const otpLoginSendSQL = `ALTER TABLE identity_mfa.continuations
 ADD COLUMN otp_send_command_id bytea CHECK(octet_length(otp_send_command_id)=16),
 ADD COLUMN otp_send_factor_id text COLLATE "C",
 ADD COLUMN otp_send_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.mfa.otp-send' CHECK(otp_send_purpose='identity.mfa.otp-send'),
 ADD CONSTRAINT mfa_otp_login_send_attribution CHECK(num_nonnulls(otp_send_command_id,otp_send_factor_id) IN(0,2)),
 ADD CONSTRAINT mfa_otp_login_send_command FOREIGN KEY(tenant_id,otp_send_purpose,otp_send_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 ADD CONSTRAINT mfa_otp_login_send_factor FOREIGN KEY(tenant_id,user_id,otp_send_factor_id) REFERENCES identity_mfa.otp_factors(tenant_id,user_id,factor_id);
CREATE UNIQUE INDEX mfa_otp_login_send_command_unique ON identity_mfa.continuations(tenant_id,otp_send_command_id) WHERE otp_send_command_id IS NOT NULL;
`
