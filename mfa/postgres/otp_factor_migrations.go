package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// OTPFactorMigrationSource appends pending/confirmed OTP-factor storage after
// shared factor references. It stores exact identifier/version references, not
// destinations, generated/submitted codes or authentication decisions. The OTP
// owner retains its challenge/digest/attempt state. Existing TOTP history and
// writers remain separate; selecting this history does not enable an OTP route.
type OTPFactorMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns forward-only owned SQL without IO. Base must contain factor
// references and the kernel identifier history; absent objects fail during
// application. Version is permanently allocated in the owned MFA namespace.
func (s OTPFactorMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_otp_factors",
		migrations.TransactionModeDefault, otpFactorSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

// State is explicit: 1 pending, 2 confirmed, 3 revoked. Confirmation's original
// command/version attribution is retained on revocation; recipient references
// are erased. A verified address is never interpreted as confirmed enrollment.
// Identity registration shares the same transaction and collision guard as TOTP.
const otpFactorSQL = `CREATE TABLE identity_mfa.otp_factors (
 tenant_id identity.directory_id NOT NULL,
 user_id identity.directory_id NOT NULL,
 factor_id text COLLATE "C" NOT NULL CHECK(factor_id ~ '^[A-Za-z0-9_-]{22}$'),
 state smallint NOT NULL CHECK(state BETWEEN 1 AND 3),
 enrollment_version identity.version NOT NULL,
 row_version identity.version NOT NULL,
 channel text COLLATE "C" NOT NULL CHECK(channel IN('email','sms')),
 identifier_id identity.directory_id,
 identifier_version identity.version,
 verification_version identity.version,
 created_command_id bytea NOT NULL CHECK(octet_length(created_command_id)=16),
 created_purpose text COLLATE "C" NOT NULL CHECK(created_purpose='identity.mfa.enable'),
 created_at timestamptz NOT NULL CHECK(isfinite(created_at)),
 enrollment_expires_at timestamptz NOT NULL CHECK(isfinite(enrollment_expires_at) AND enrollment_expires_at>created_at AND enrollment_expires_at<=created_at+interval '15 minutes'),
 confirmed_at timestamptz CHECK(isfinite(confirmed_at) AND confirmed_at>=created_at AND confirmed_at<enrollment_expires_at),
 activation_command_id bytea CHECK(octet_length(activation_command_id)=16),
 activation_before_version identity.version,
 activation_authority_before identity.version,
 activation_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.mfa.otp-verify' CHECK(activation_purpose='identity.mfa.otp-verify'),
 PRIMARY KEY(tenant_id,factor_id),
 UNIQUE(tenant_id,user_id,factor_id),
 UNIQUE(tenant_id,created_purpose,created_command_id),
 FOREIGN KEY(tenant_id,user_id,factor_id) REFERENCES identity_mfa.factor_references(tenant_id,user_id,factor_id),
 FOREIGN KEY(tenant_id,user_id,identifier_id) REFERENCES identity.identifiers(tenant_id,user_id,identifier_id),
 FOREIGN KEY(tenant_id,created_purpose,created_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 FOREIGN KEY(tenant_id,activation_purpose,activation_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id),
 CHECK(num_nonnulls(activation_command_id,activation_before_version,activation_authority_before,confirmed_at) IN(0,4)),
 CHECK((state=1 AND num_nonnulls(identifier_id,identifier_version,verification_version)=3 AND confirmed_at IS NULL) OR
       (state=2 AND num_nonnulls(identifier_id,identifier_version,verification_version)=3 AND confirmed_at IS NOT NULL) OR
       (state=3 AND num_nonnulls(identifier_id,identifier_version,verification_version)=0))
);
CREATE TRIGGER mfa_otp_factor_reference BEFORE INSERT OR UPDATE OF tenant_id,user_id,factor_id ON identity_mfa.otp_factors
 FOR EACH ROW EXECUTE FUNCTION identity_mfa.register_factor_reference_v1('otp');
CREATE INDEX mfa_pending_otp_expiry ON identity_mfa.otp_factors(enrollment_expires_at,tenant_id,factor_id) WHERE state=1;
CREATE UNIQUE INDEX mfa_otp_activation_command_unique ON identity_mfa.otp_factors(tenant_id,activation_command_id) WHERE activation_command_id IS NOT NULL;
ALTER TABLE identity_mfa.recovery_sets
 ADD COLUMN otp_factor_id text COLLATE "C" GENERATED ALWAYS AS(CASE WHEN factor_method='otp' THEN factor_id END) STORED,
 ADD CONSTRAINT mfa_recovery_otp_factor_fk FOREIGN KEY(tenant_id,user_id,otp_factor_id) REFERENCES identity_mfa.otp_factors(tenant_id,user_id,factor_id);
`
