package reference

import (
	"context"

	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Completion extends the already selected native histories in owner order. It
// never copies a store or resets old windows/session rows. The verification
// predecessor is required even in graphs that do not expose registration.
func magicLinkTOTPRequiredMigrations(ctx context.Context, catalog []migrationHistory, schema, riskSchema string) ([]migrationHistory, error) {
	hasVerification := false
	for _, history := range catalog {
		if history.namespace == "identity_registration_counters" {
			hasVerification = true
		}
	}
	if !hasVerification {
		steps, err := (riskpg.VerificationCounterMigrationSource{Schema: riskSchema, Version: 1}).Load(ctx)
		if err != nil {
			return nil, err
		}
		catalog = append(catalog, migrationHistory{namespace: "identity_registration_counters", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/risk/postgres"}})
	}
	steps, err := (riskpg.MFACompletionCounterMigrationSource{Schema: riskSchema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_mfa_counters", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/risk/postgres"}})
	profile, err := (sessionpg.MFAMigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	issuance, err := (sessionpg.MFASigninMigrationSource{Schema: schema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_magiclink_mfa_session", history: append(profile, issuance...), owners: map[migrations.Version]ModuleID{1: "identity/session/postgres", 2: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, constraints: []string{"sessions.session_record_binding_v6", "sessions.session_credential_continuation_v3"}}, {version: 2, schema: schema, constraints: []string{"session_issuances.session_issuances_purpose_v6"}}}})
	return catalog, nil
}
