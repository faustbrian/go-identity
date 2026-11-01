package reference

import (
	"context"

	authority "github.com/faustbrian/go-authorization/v3/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	oauthpg "github.com/faustbrian/go-oauth-server/postgres"
)

// Retain the existing shared kernel/risk prefix byte for byte. This separate
// workload lineage installs only owner-supplied forward suffixes; it does not
// insert older steps beneath a previously installed human-session history.
func (s StoreSet) oauthWorkloadMigrationCatalog(ctx context.Context, catalog []migrationHistory) ([]migrationHistory, error) {
	n := s.state.features.oauthWorkload
	base := fixedMigrationSource(catalog[0].history)
	prepared := kernel.PreparationMigrationSource{Base: base, Version: 1012}
	admission := kernel.AdmissionPreparationMigrationSource{Base: prepared, Version: 1013}
	status := kernel.StatusMigrationSource{Base: admission, Version: 1014}
	credentials := kernel.CredentialMigrationSource{Base: status, Version: 1015}
	directory := kernel.DirectoryAuthorityMigrationSource{Base: credentials, Version: 1016, GlobalAuthorityID: n.global, TenantIDs: n.tenants}
	keyed := kernel.RequestKeyMigrationSource{Base: directory, Version: 1017}
	full, err := (kernel.RequestKeyPreparationMigrationSource{Base: keyed, Version: 1018}).Load(ctx)
	if err != nil {
		return nil, err
	}
	owned := migrationHistory{namespace: "identity_oauth_kernel", history: full[len(catalog[0].history):], owners: make(map[migrations.Version]ModuleID)}
	for _, step := range owned.history {
		owned.owners[step.Version()] = "identity/postgres"
	}
	for _, guard := range sharedSuffixGuards(s.state.config.Schema) {
		if _, selected := owned.owners[guard.version]; selected {
			owned.guards = append(owned.guards, guard)
		}
	}
	catalog = append(catalog, owned)
	catalog, err = counterPreparationMigrationCatalog(ctx, catalog)
	if err != nil {
		return nil, err
	}
	riskBase := riskpg.MigrationSource{Schema: s.state.config.Schema, Version: 1000}
	issued := riskpg.IssuanceIDMigrationSource{Base: riskBase, Version: 1001}
	reserved := riskpg.ReservationMigrationSource{Base: issued, Version: 1002}
	counters := riskpg.CounterMigrationSource{Base: reserved, Version: 1003}
	lockouts, err := (riskpg.LockoutMigrationSource{Base: counters, Version: 2000}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_oauth_risk", history: lockouts[len(lockouts)-1:], owners: map[migrations.Version]ModuleID{2000: "identity/risk/postgres"}, guards: []migrationGuard{{version: 2000, schema: s.state.config.Schema, tables: []string{"counter_lockouts", "risk_lockout_expiry"}}}})
	auth, err := authority.AuthoritySchemaMigration(1300)
	if err != nil {
		return nil, err
	}
	step, err := migrations.NewMigration(migrations.Version(auth.Version), auth.Name, migrations.TransactionModeDefault, auth.Up, auth.Down)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_oauth_authorization", history: []migrations.Migration{step}, owners: map[migrations.Version]ModuleID{step.Version(): "authorization/postgres"}, guards: []migrationGuard{{version: step.Version(), schema: "public", tables: []string{"authorization_subject_authorities"}}}})
	protocol, err := (oauthpg.WorkloadMigrationSource{Base: oauthpg.MigrationSource{Schema: n.schema, Version: 1}, Schema: n.schema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, migrationHistory{namespace: "identity_oauth", history: protocol, owners: map[migrations.Version]ModuleID{1: "oauth-server/postgres", 2: "oauth-server/postgres"}, guards: []migrationGuard{
		{version: 1, schema: n.schema},
		{version: 1, schema: n.schema, tables: []string{"grants", "artifacts", "effects"}},
		{version: 2, schema: n.schema, columns: []string{"grants.workload_source", "grants.workload_only", "artifacts.workload_only"}, constraints: []string{"grants.grants_typed_subject", "grants.grants_typed_reference", "artifacts.artifacts_typed_parent", "artifacts.artifacts_workload_access_only", "artifacts.artifacts_typed_root"}},
	}})
	return infrastructureMigrationCatalog(ctx, catalog)
}
