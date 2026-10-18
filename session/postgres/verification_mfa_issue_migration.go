package postgres

import (
	"context"
	"strings"

	migrations "github.com/faustbrian/go-migrations/v3"
)

// EmailVerificationMFASigninMigrationSource extends issuance after the installed
// verification-first v7 history. It preserves that history and all populated
// verification rows while adding the native factor-completion purposes under
// a new v8 constraint. Install MFAMigrationSource's session-record suffix first.
// This is not the historical MFA-before-verification lineage; never substitute
// it for an applied migration. The caller allocates an unused Version and the
// existing runner owns locks, validation and transactional commitment.
type EmailVerificationMFASigninMigrationSource struct {
	Schema  string
	Version migrations.Version
}

// Load constructs one forward-only purpose extension without IO or callbacks.
// Missing predecessor constraints fail during apply; no baselining or IF EXISTS
// fallback is generated. Invalid configuration and cancellation retain their
// existing native migration error semantics.
func (s EmailVerificationMFASigninMigrationSource) Load(ctx context.Context) ([]migrations.Migration, error) {
	previous, err := (MFASigninMigrationSource{Schema: s.Schema, Version: s.Version}).Load(ctx)
	if err != nil {
		return nil, err
	}
	sql := strings.NewReplacer("session_issuances_purpose_v5", "session_issuances_purpose_v7", "session_issuances_purpose_v6", "session_issuances_purpose_v8", "'identity.session.issue'", "'identity.email.verification-signin','identity.session.issue'").Replace(previous[0].UpSQL())
	step, err := migrations.NewMigration(s.Version, "identity_session_verification_mfa_signin", migrations.TransactionModeDefault, sql, "")
	if err != nil {
		return nil, err
	}
	return []migrations.Migration{step}, nil
}
