package reference

import (
	"context"
	"slices"
	"time"

	capabilitypg "github.com/faustbrian/go-capability/postgres/identity"
	identity "github.com/faustbrian/go-identity"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
	database "github.com/faustbrian/go-postgres"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// OAuthProxyProductionMigrationConfiguration selects a dedicated production
// proxy database. Schema, GlobalAuthorityID and TenantID must match the service
// deployment. HTTPRiskSchema opts into the durable risk and HTTP rate histories;
// empty selects only native production custody. Timeout bounds each operation
// (1ms..1m). Nil Apply allows only Check and Plan. Apply selects its own trusted
// operator command scope. Keep the installed schema and authority IDs unchanged.
type OAuthProxyProductionMigrationConfiguration struct {
	Schema, GlobalAuthorityID, HTTPRiskSchema string
	TenantID                                  identity.TenantID
	Timeout                                   time.Duration
	Apply                                     *MigrationApplyPolicy
}

// OAuthProxyProductionMigrations is the migration-only view of the existing
// Reference operator. It owns no provider, handler or database connection.
type OAuthProxyProductionMigrations struct {
	stores  StoreSet
	modules []ModuleID
}

// NewOAuthProxyProductionMigrations freezes the exact selected native histories
// without I/O. It installs nothing and never adopts unmanaged histories. Close
// the returned owner before releasing its caller-owned migration pool. That
// pool may use a separate migration role from the runtime pool.
func NewOAuthProxyProductionMigrations(pool *database.Pool, c OAuthProxyProductionMigrationConfiguration) (OAuthProxyProductionMigrations, error) {
	invalid := identity.InvalidInputError{Field: "reference_oauth_proxy_production_migrations"}
	if pool == nil || pool.Raw() == nil || c.Timeout < time.Millisecond || c.Timeout > time.Minute ||
		c.Schema == "audit" || c.HTTPRiskSchema == "audit" || c.HTTPRiskSchema != "" && c.HTTPRiskSchema == c.Schema {
		return OAuthProxyProductionMigrations{}, invalid
	}
	policy, err := copyMigrationApplyPolicy(c.Apply)
	if err != nil {
		return OAuthProxyProductionMigrations{}, invalid
	}
	history, err := productionProxyMigrationCatalog(context.Background(), c)
	if err != nil {
		return OAuthProxyProductionMigrations{}, invalid
	}
	modules := make([]ModuleID, 0, len(history))
	for _, h := range history {
		owner := h.owners[h.history[0].Version()]
		modules = append(modules, owner)
	}
	slices.Sort(modules)
	lifetime, cancel := context.WithCancel(context.Background())
	drained := make(chan struct{})
	close(drained)
	stores := StoreSet{state: &storeState{
		pool: pool, lifetime: lifetime, cancel: cancel, drained: drained, durable: true,
		config: VelocityStoreConfiguration{PrimaryTimeout: c.Timeout}, migrations: policy, productionProxyHistory: history,
	}}
	return OAuthProxyProductionMigrations{stores: stores, modules: modules}, nil
}

// Check inspects all selected ledgers without writing or enabling runtime use.
func (m OAuthProxyProductionMigrations) Check(ctx context.Context) (ReferenceMigrationCheckResult, error) {
	return m.stores.ReferenceMigrationCheck(ctx, ReferenceMigrationCheckRequest{Modules: m.modules})
}

// Plan describes only the pending steps of the complete selected graph.
func (m OAuthProxyProductionMigrations) Plan(ctx context.Context) (ReferenceMigrationPlanResult, error) {
	return m.stores.ReferenceMigrationPlan(ctx, ReferenceMigrationPlanRequest{Modules: m.modules})
}

// Apply runs or resumes the exact Plan with the existing idempotent operator.
// Partial or foreign module selections and stale plans cannot install anything.
func (m OAuthProxyProductionMigrations) Apply(ctx context.Context, req ReferenceMigrationApplyRequest) (ReferenceMigrationApplyResult, error) {
	ids := make([]ModuleID, 0, len(m.modules))
	if len(req.Plan.Modules) != len(m.modules) {
		return ReferenceMigrationApplyResult{}, identity.InvalidInputError{Field: "reference_modules"}
	}
	for _, module := range req.Plan.Modules {
		ids = append(ids, ModuleID(module.Module))
	}
	slices.Sort(ids)
	if !slices.Equal(ids, m.modules) {
		return ReferenceMigrationApplyResult{}, identity.InvalidInputError{Field: "reference_modules"}
	}
	return m.stores.ReferenceMigrationApply(ctx, req)
}

// Close cancels and joins operator work, without closing the borrowed pool.
func (m OAuthProxyProductionMigrations) Close(ctx context.Context) error { return m.stores.Close(ctx) }

func productionProxyMigrationCatalog(ctx context.Context, c OAuthProxyProductionMigrationConfiguration) ([]migrationHistory, error) {
	directory := kernel.DirectoryAuthorityMigrationSource{Base: kernel.MigrationSource{}, Version: 10,
		GlobalAuthorityID: c.GlobalAuthorityID, TenantIDs: []identity.TenantID{c.TenantID}}
	keyed := kernel.RequestKeyMigrationSource{Base: directory, Version: 11}
	keyPreparation := kernel.RequestKeyPreparationMigrationSource{Base: keyed, Version: 12}
	keyExpiry := kernel.RequestKeyExpiryMigrationSource{Base: keyPreparation, Version: 13}
	prepared := kernel.PreparationMigrationSource{Base: keyExpiry, Version: 14}
	admission := kernel.AdmissionPreparationMigrationSource{Base: prepared, Version: 15}
	counted := kernel.CounterPreparationMigrationSource{Base: admission, Version: 16}
	forward := kernel.OAuthProxyForwardPreparationErasureMigrationSource{Base: counted, Version: 17}
	steps, err := (kernel.OAuthProxyStartPreparationErasureMigrationSource{Base: forward, Version: 18}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog := []migrationHistory{proxyOwnedHistory("identity_oauth_proxy_kernel", "identity/postgres", steps,
		migrationGuard{version: 1, schema: "identity"},
		migrationGuard{version: 10, schema: "identity", tables: []string{"global_authorities", "tenant_authorities"}},
		migrationGuard{version: 11, schema: "identity", tables: []string{"request_key_namespaces", "request_key_mappings"}},
		migrationGuard{version: 14, schema: "identity", columns: []string{"commands.preparation_profile"}},
		migrationGuard{version: 16, schema: "identity", columns: []string{"commands.preparation_declaration"}},
	)}
	base, err := (oauthpg.MigrationSource{Schema: c.Schema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	proxy, err := (oauthpg.ProxyTransactionMigrationSource{Schema: c.Schema, Version: 2}).Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, proxyOwnedHistory("identity_oauth_proxy", "identity/oauth/postgres", append(base, proxy...),
		migrationGuard{version: 1, schema: c.Schema},
		migrationGuard{version: 2, schema: c.Schema, tables: []string{"proxy_transactions"}},
	))
	capability, err := migrations.NewFSSource(ownedMigrationFiles{capabilitypg.Migrations()}, ".")
	if err != nil {
		return nil, err
	}
	proofs, err := capability.Load(ctx)
	if err != nil {
		return nil, err
	}
	catalog = append(catalog, proxyOwnedHistory("identity_capability", "capability/postgres/identity", proofs,
		migrationGuard{version: 1, schema: "public", tables: []string{"capability_identity_one_use"}},
	))
	catalog, err = infrastructureMigrationCatalog(ctx, catalog)
	if err != nil || c.HTTPRiskSchema == "" {
		return catalog, err
	}
	counters, err := (riskpg.DurableCounterMigrationSource{Schema: c.HTTPRiskSchema, Version: 1}).Load(ctx)
	if err != nil {
		return nil, err
	}
	nativeRate := ratepg.SchemaMigration()
	rate, err := migrations.NewMigration(migrations.Version(nativeRate.Version), nativeRate.Name, migrations.TransactionModeDefault, nativeRate.Up, nativeRate.Down)
	if err != nil {
		return nil, err
	}
	return append(catalog,
		proxyOwnedHistory("identity_durable_admission", "identity/risk/postgres", counters,
			migrationGuard{version: 1, schema: c.HTTPRiskSchema, tables: []string{"durable_counter_scopes", "durable_counter_keys", "durable_counter_windows", "durable_counter_aliases", "durable_counter_attempts"}}),
		proxyOwnedHistory("identity_http_rate", "rate-limit/postgres", []migrations.Migration{rate},
			migrationGuard{version: rate.Version(), schema: "public", tables: []string{"rate_limit_states", "rate_limit_states_expires_at_idx"}}),
	), nil
}

func proxyOwnedHistory(namespace string, owner ModuleID, history []migrations.Migration, guards ...migrationGuard) migrationHistory {
	h := migrationHistory{namespace: namespace, history: history, guards: guards, owners: make(map[migrations.Version]ModuleID, len(history))}
	for _, step := range history {
		h.owners[step.Version()] = owner
	}
	return h
}
