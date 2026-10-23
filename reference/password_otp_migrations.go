package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// OTP suffixes retain independent permanent ledgers. They do not occupy the
// shared MFA namespace's optional management allocations8..12 or rewrite a
// populated predecessor. TOTP/recovery record/counter predecessors are storage
// support only: installing them enables no alternate login or HTTP operation.
func passwordOTPMigrationCatalog(ctx context.Context, catalog []migrationHistory, schema, riskSchema string) ([]migrationHistory, error) {
	invalid := identity.InvalidInputError{Field: "reference_password_otp_history"}
	var base []migrations.Migration
	var recoveryCounters, recoverySessions bool
	for _, h := range catalog {
		switch h.namespace {
		case "identity_mfa":
			base = h.history
		case "identity_mfa_recovery_counters":
			recoveryCounters = true
		case "identity_mfa_recovery_session":
			recoverySessions = true
		case "identity_mfa_otp", "identity_mfa_otp_counters", "identity_mfa_otp_session":
			return nil, invalid
		}
	}
	if len(base) < 7 || !recoveryCounters || !recoverySessions {
		return nil, invalid
	}
	factors, err := mfaOTPFactorHistory(ctx, catalog, true)
	if err != nil {
		return nil, err
	}
	sendCounters, err := (riskpg.MFALoginSendCounterMigrationSource{Schema: riskSchema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	completionCounters, err := (riskpg.MFAOTPCompletionCounterMigrationSource{Schema: riskSchema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	profiles, err := (sessionpg.MFAOTPRecordMigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog,
		factors,
		migrationHistory{namespace: "identity_mfa_otp_counters", history: append(sendCounters, completionCounters...), owners: map[migrations.Version]ModuleID{1: "identity/risk/postgres", 2: "identity/risk/postgres"}},
		migrationHistory{namespace: "identity_mfa_otp_session", history: profiles, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, constraints: []string{"sessions.session_record_binding_v9", "sessions.session_credential_continuation_v6"}}}},
	), nil
}

// OTP enrollment and login share these permanent allocations and exact bytes.
// Enrollment alone installs no continuation-send or session-issuance suffix.
func mfaOTPFactorHistory(ctx context.Context, catalog []migrationHistory, login bool) (migrationHistory, error) {
	invalid := identity.InvalidInputError{Field: "reference_mfa_otp_history"}
	var base []migrations.Migration
	for _, h := range catalog {
		if h.namespace == "identity_mfa_otp" {
			return migrationHistory{}, invalid
		}
		if h.namespace == "identity_mfa" {
			if base != nil {
				return migrationHistory{}, invalid
			}
			base = h.history
		}
	}
	if len(base) < 6 {
		return migrationHistory{}, invalid
	}
	var source migrations.Source = mfapg.FactorReferenceMigrationSource{Base: fixedMigrationSource(base), Version: 13}
	source = mfapg.OTPFactorMigrationSource{Base: source, Version: 14}
	source = mfapg.OTPSendMigrationSource{Base: source, Version: 15}
	full, err := source.Load(ctx)
	if err != nil {
		return migrationHistory{}, err
	}
	h := migrationHistory{namespace: "identity_mfa_otp", history: append([]migrations.Migration(nil), full[len(base):]...), owners: map[migrations.Version]ModuleID{13: "identity/mfa/postgres", 14: "identity/mfa/postgres", 15: "identity/mfa/postgres"}, guards: []migrationGuard{
		{version: 13, schema: "identity_mfa", tables: []string{"factor_references"}, columns: []string{"recovery_sets.factor_method"}},
		{version: 14, schema: "identity_mfa", tables: []string{"otp_factors"}},
		{version: 15, schema: "identity_mfa", columns: []string{"otp_factors.last_send_command_id"}},
	}}
	if login {
		steps, err := (mfapg.OTPLoginSendMigrationSource{Version: 16}).Load(ctx)
		if err != nil {
			return migrationHistory{}, err
		}
		h.history = append(h.history, steps...)
		h.owners[16] = "identity/mfa/postgres"
		h.guards = append(h.guards, migrationGuard{version: 16, schema: "identity_mfa", columns: []string{"continuations.otp_send_command_id"}})
	}
	return h, nil
}
