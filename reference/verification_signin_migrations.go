package reference

import (
	"context"

	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Select the real session-owned predecessor without enabling general magic-link
// login. This independent suffix never changes applied migration bytes.
func (s StoreSet) verificationSigninMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features.verificationSignin == nil {
		return catalog, nil
	}
	schema := s.state.features.migrations.passwordSigninSchema
	lineage := s.state.features.verificationSessionLineage
	verificationFirst := lineage == VerificationBeforeMFA
	magic, mfa := false, false
	for _, h := range catalog {
		magic = magic || h.namespace == "identity_magiclink_session"
		mfa = mfa || h.namespace == "identity_magiclink_mfa_session"
	}
	if !magic {
		var err error
		catalog, err = magicLinkMigrationCatalog(ctx, catalog, schema)
		if err != nil {
			return nil, err
		}
	}
	if (lineage == MFABeforeVerification || s.state.features.verificationTOTP != nil && !verificationFirst) && !mfa {
		var err error
		catalog, err = magicLinkTOTPRequiredMigrations(ctx, catalog, schema, s.state.config.Schema, false)
		if err != nil {
			return nil, err
		}
		mfa = true
	}
	if verificationFirst {
		mfa = false
	}
	steps, err := (sessionpg.EmailVerificationSigninMigrationSource{Schema: schema, Version: 1, MFASignin: mfa}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_verification_signin_session", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, tables: []string{"session_issuances_verification_parent_unique"}, columns: []string{"session_issuances.verification_command_id"}, constraints: []string{"session_issuances.session_issuances_purpose_v7", "session_issuances.session_issuances_verification_parent"}}}})
	selected := s.state.features.migrations
	if verificationFirst && (s.state.features.verificationTOTP != nil || selected.magicTOTP || selected.passwordTOTP || selected.passwordRecovery || selected.passwordOTP) {
		catalog, err = magicLinkTOTPRequiredMigrations(ctx, catalog, schema, s.state.config.Schema, true)
		if err != nil {
			return nil, err
		}
		// These immutable record-format successors need the shared MFA format
		// installed by the new verification-first suffix, not an older purpose
		// migration replayed against already populated verification issuances.
		var followers, prior []migrationHistory
		for _, h := range catalog {
			switch h.namespace {
			case "identity_password_mfa_session", "identity_mfa_recovery_session", "identity_mfa_otp_session":
				followers = append(followers, h)
			default:
				prior = append(prior, h)
			}
		}
		profile, e := (sessionpg.MFAMigrationSource{Schema: schema, Version: 1}).Load(ctx)
		if e != nil {
			return nil, e
		}
		issuance, e := (sessionpg.EmailVerificationMFASigninMigrationSource{Schema: schema, Version: 2}).Load(ctx)
		if e != nil {
			return nil, e
		}
		bridge := migrationHistory{namespace: "identity_verification_mfa_session", history: append(profile, issuance...), owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, constraints: []string{"sessions.session_record_binding_v6", "sessions.session_credential_continuation_v3"}}, {version: 2, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_v8"}}}}
		catalog = append(append(prior, bridge), followers...)
	}
	if !s.state.features.verificationSigninMFA {
		return catalog, nil
	}
	// Preserve the permanently allocated MFA prefix, including password's
	// forward origin constraint, before this independently selected suffix.
	prefix := false
	for _, h := range catalog {
		if h.namespace == "identity_mfa" {
			for _, m := range h.history {
				prefix = prefix || m.Version() == 7
			}
		}
	}
	if !prefix {
		catalog, err = passwordTOTPMigrationCatalog(ctx, catalog, schema, s.state.config.Schema, false, verificationFirst)
		if err != nil {
			return nil, err
		}
	}
	forward, err := (mfapg.VerificationContinuationMigrationSource{Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog, migrationHistory{namespace: "identity_verification_mfa", history: forward, owners: map[migrations.Version]ModuleID{1: "identity/mfa/postgres"}, guards: []migrationGuard{{version: 1, schema: "identity_mfa", constraints: []string{"continuations.continuations_origin_purpose_v2"}}}}), nil
}
