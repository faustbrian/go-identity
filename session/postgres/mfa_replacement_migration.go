package postgres

import (
	"context"
	"strings"

	migrations "github.com/faustbrian/go-migrations/v3"
	"github.com/jackc/pgx/v5"
)

// MFATOTPReplacementSessionMigrationSource appends the exact confirmation
// disposition purpose without rewriting installed regeneration/update/disable
// histories. Disable remains independently optional; allocate a fixed suffix.
type MFATOTPReplacementSessionMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load returns one forward-only transactional migration without IO. Existing
// disposition and factor-update prefixes must already be installed.
func (s MFATOTPReplacementSessionMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	if _, err := (MFARecoverySessionMigrationSource{Schema: s.Schema, Version: s.Version}).Load(ctx); err != nil {
		return nil, err
	}
	m, err := migrations.NewMigration(s.Version, "identity_mfa_totp_replacement_session_effects", migrations.TransactionModeDefault, strings.ReplaceAll(replacementSessionSQL, "@schema@", pgx.Identifier{s.Schema}.Sanitize()), "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{m}, nil
}

const replacementSessionSQL = `ALTER TABLE @schema@.mfa_recovery_dispositions
 DROP CONSTRAINT mfa_recovery_dispositions_purpose_check,
 ADD CONSTRAINT mfa_recovery_dispositions_purpose_check
 CHECK(purpose IN('identity.mfa.recovery-regenerate','identity.mfa.factor-update','identity.mfa.disable','identity.mfa.totp-verify'));`
