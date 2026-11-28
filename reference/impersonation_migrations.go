package reference

import (
	"context"

	impersonationpg "github.com/faustbrian/go-identity/impersonation/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func (s StoreSet) impersonationMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	if s.state.features == nil || s.state.features.impersonation == nil {
		return catalog, nil
	}
	// The required password/TOTP profile has already selected its common
	// counter, lockout and session predecessors in baseMigrationCatalog.
	steps, err := (impersonationpg.SelfStopMigrationSource{}).Load(ctx)
	if err != nil {
		return nil, err
	}
	owners := make(map[migrations.Version]ModuleID, len(steps))
	for _, step := range steps {
		owners[step.Version()] = "identity/impersonation/postgres"
	}
	return append(catalog, migrationHistory{
		namespace: "identity_impersonation",
		history:   steps,
		owners:    owners,
		guards: []migrationGuard{
			{version: 1, schema: "identity_impersonation", tables: []string{"grants", "approvals"}, functions: []string{"preserve_request", "preserve_approval"}},
			{version: 2, schema: "identity_impersonation", tables: []string{"active_grants"}, functions: []string{"preserve_activation"}},
			{version: 3, schema: "identity_impersonation", tables: []string{"revocations"}, functions: []string{"preserve_revocation"}},
			{version: 4, schema: "identity_impersonation", functions: []string{"reject_revoked_approval"}},
			{version: 5, schema: "identity_impersonation", functions: []string{"reject_revoked_activation", "revocation_ready"}},
			{version: 6, schema: "identity_impersonation", tables: []string{"stop_proofs", "stops"}, functions: []string{"preserve_stop_proof", "preserve_stop"}},
		},
	}), nil
}
