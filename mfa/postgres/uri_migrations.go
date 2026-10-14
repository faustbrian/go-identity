package mfapostgres

import (
	"context"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// URIRevealMigrationSource appends exact reveal-command attribution without
// changing prior migrations or resetting historical reveal_consumed markers.
// Historical consumed rows without attribution remain non-revealable. Version
// must follow the owned recovery history. No factor is enrolled or backfilled.
type URIRevealMigrationSource struct {
	Base    migrations.Source
	Version migrations.Version
}

// Load returns forward-only owned SQL using the existing MFA migration bounds.
func (s URIRevealMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	base, err := (TOTPFactorMigrationSource{Base: s.Base, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	forward, err := migrations.NewMigration(s.Version, "identity_mfa_uri_reveal", migrations.TransactionModeDefault, uriRevealSQL, "")
	if err != nil {
		return nil, err
	}
	base[len(base)-1] = forward
	return base, nil
}

const uriRevealSQL = `ALTER TABLE identity_mfa.totp_factors
 ADD COLUMN reveal_command_id bytea CHECK(octet_length(reveal_command_id)=16),
 ADD COLUMN reveal_before_version identity.version,
 ADD COLUMN reveal_purpose text COLLATE "C" NOT NULL DEFAULT 'identity.mfa.totp-uri' CHECK(reveal_purpose='identity.mfa.totp-uri'),
 ADD CONSTRAINT mfa_reveal_attribution CHECK ((reveal_command_id IS NULL AND reveal_before_version IS NULL) OR (reveal_consumed AND reveal_command_id IS NOT NULL AND reveal_before_version IS NOT NULL)),
 ADD CONSTRAINT mfa_reveal_command FOREIGN KEY(tenant_id,reveal_purpose,reveal_command_id) REFERENCES identity.commands(tenant_id,purpose,command_id);
CREATE UNIQUE INDEX mfa_reveal_command_unique ON identity_mfa.totp_factors(tenant_id,reveal_command_id) WHERE reveal_command_id IS NOT NULL;
`
