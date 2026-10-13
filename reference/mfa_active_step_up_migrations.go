package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

// Keep the common MFA suffix allocation independent of which login profile was
// installed first. Version7 remains reserved for password continuation history;
// optional active-proof storage occupies version8 and preserves populated rows.
func (s StoreSet) activeStepUpMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features.mfaEnrollment == nil || s.state.features.mfaEnrollment.stepup == nil {
		return catalog, nil
	}
	for i, h := range catalog {
		if h.namespace != "identity_mfa" {
			continue
		}
		steps, err := (mfapg.FactorVerificationMigrationSource{Base: fixedMigrationSource(h.history), Version: 8}).Load(ctx)
		if err != nil {
			return nil, err
		}
		owners := make(map[migrations.Version]ModuleID, len(h.owners)+1)
		for v, owner := range h.owners {
			owners[v] = owner
		}
		owners[8] = "identity/mfa/postgres"
		catalog[i] = migrationHistory{namespace: h.namespace, history: steps, owners: owners, guards: append(append([]migrationGuard(nil), h.guards...), migrationGuard{version: 8, schema: "identity_mfa", tables: []string{"factor_verifications"}})}
		if s.state.features.mfaEnrollment.regenerate != nil {
			schema := s.state.features.migrations.passwordSigninSchema
			steps, err := (sessionpg.MFARecoverySessionMigrationSource{Schema: schema, Version: 1}).Load(ctx)
			if err != nil {
				return nil, err
			}
			catalog = append(catalog, migrationHistory{namespace: "identity_mfa_recovery_dispositions", history: steps, owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: schema, tables: []string{"mfa_recovery_dispositions"}}}})
		}
		return catalog, nil
	}
	return nil, identity.InvalidInputError{Field: "reference_mfa_step_up_history"}
}
