package reference

import (
	"context"

	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Append native-owned forward suffixes after the complete password MFA history.
// Permanent namespaces preserve old checksums when recovery is selected later.
func recoveryCompletionMigrationCatalog(ctx context.Context, catalog []migrationHistory, schema, riskSchema string) ([]migrationHistory, error) {
	counters, err := (riskpg.MFARecoveryCounterMigrationSource{Schema: riskSchema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	profiles, err := (sessionpg.MFARecoveryMigrationSource{Schema: schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	return append(catalog,
		migrationHistory{namespace: "identity_mfa_recovery_counters", history: counters, owners: map[migrations.Version]ModuleID{1: "identity/risk/postgres"}},
		migrationHistory{namespace: "identity_mfa_recovery_session", history: profiles, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, constraints: []string{"sessions.session_record_binding_v8", "sessions.session_credential_continuation_v5"}}}},
	), nil
}
