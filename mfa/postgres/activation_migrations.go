package mfapostgres

import (
	"context"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// TOTPActivationMigrationSource appends durable confirmation attribution.
// Existing active factors retain their historical state without fabricated
// command ownership. Version must follow the URI reveal migration.
type TOTPActivationMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load preserves prior history and returns owned forward-only migration SQL.
func (s TOTPActivationMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	history, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_totp_activation", migrations.TransactionModeDefault, totpActivationSQL, "")
	if err != nil {
		return nil, err
	}
	history[len(history)-1] = forward
	return history, nil
}

const totpActivationSQL = `ALTER TABLE identity_mfa.totp_factors
 ADD COLUMN activation_command_id bytea CHECK(octet_length(activation_command_id)=16),
 ADD COLUMN activation_before_version identity.version,
 ADD COLUMN activation_authority_before identity.version,
 ADD COLUMN activation_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.mfa.totp-verify' CHECK(activation_purpose='identity.mfa.totp-verify'),
 ADD CONSTRAINT mfa_activation_attribution CHECK(num_nonnulls(activation_command_id,activation_before_version,activation_authority_before) IN(0,3) AND (activation_command_id IS NULL OR (state IN(2,3) AND confirmed_at IS NOT NULL))),
 ADD CONSTRAINT mfa_activation_command FOREIGN KEY(tenant_id,activation_purpose,activation_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id);
CREATE UNIQUE INDEX mfa_activation_command_unique ON identity_mfa.totp_factors(tenant_id,activation_command_id) WHERE activation_command_id IS NOT NULL;
`
