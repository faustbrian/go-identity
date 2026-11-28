package reference

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	migrations "github.com/faustbrian/go-migrations/v3"
)

func TestOAuthProxyMaintenanceProductionPreservesInstalledHistories(t *testing.T) {
	c := OAuthProxyProductionMigrationConfiguration{
		Schema: "production_oauth", GlobalAuthorityID: "synthetic-deployment",
		TenantID: identity.TenantID("AAAAAAAAAAAAAAAAAAAAAQ"), HTTPRiskSchema: "production_risk",
	}
	legacy := maintenanceLoadSources(t,
		oauthpg.MigrationSource{Schema: c.Schema, Version: 1},
		oauthpg.ProxyTransactionMigrationSource{Schema: c.Schema, Version: 2},
		oauthpg.ProviderAuthorityMigrationSource{Schema: c.Schema, Version: 3},
		oauthpg.ProxyRetirementMigrationSource{Schema: c.Schema, Version: 4, Kind: kernel.OAuthProxyRetireProduction},
	)
	for _, selection := range []struct {
		name    string
		profile productionProxyMigrationProfile
		length  int
	}{
		{name: "static", profile: productionProxyStatic, length: 2},
		{name: "provider-authority", profile: productionProxyLiveAuthority, length: 3},
		{name: "retirement", profile: productionProxyRetirement, length: 5},
		{name: "maintenance-expand", profile: productionProxyMaintenanceExpand, length: 9},
		{name: "maintenance-activate", profile: productionProxyMaintenanceActivate, length: 10},
	} {
		t.Run(selection.name, func(t *testing.T) {
			catalog, err := productionProxyMigrationCatalog(t.Context(), c, selection.profile)
			if err != nil {
				t.Fatal(err)
			}
			oauth := maintenanceHistory(t, catalog, "identity_oauth_proxy")
			if len(oauth.history) != selection.length {
				t.Fatalf("selected %d OAuth steps, want %d", len(oauth.history), selection.length)
			}
			prefixLength := min(selection.length, len(legacy))
			maintenanceEqualMigrations(t, oauth.history[:prefixLength], legacy[:prefixLength])
			for _, step := range oauth.history {
				if oauth.owners[step.Version()] != "identity/oauth/postgres" {
					t.Fatalf("migration %d lost its native OAuth owner", step.Version())
				}
			}
			if selection.profile < productionProxyMaintenanceExpand {
				return
			}
			phase := OAuthProxyMaintenanceExpand
			if selection.profile == productionProxyMaintenanceActivate {
				phase = OAuthProxyMaintenanceActivate
			}
			suffix, guards, err := proxyMaintenanceMigrationSuffix(t.Context(), c.Schema, kernel.OAuthProxyRetireProduction, phase)
			if err != nil {
				t.Fatal(err)
			}
			maintenanceEqualMigrations(t, oauth.history[len(legacy):], suffix)
			for _, guard := range guards {
				if !slices.ContainsFunc(oauth.guards, func(actual migrationGuard) bool { return reflect.DeepEqual(actual, guard) }) {
					t.Fatalf("catalog omitted unmanaged-object guard for maintenance version %d", guard.version)
				}
			}
			baseline, err := productionProxyMigrationCatalog(t.Context(), c, productionProxyRetirement)
			if err != nil || len(catalog) != len(baseline) {
				t.Fatal("maintenance changed the selected non-OAuth graph", err)
			}
			for i, before := range baseline {
				after := catalog[i]
				if before.namespace == oauth.namespace {
					if len(after.guards) < len(before.guards) || !reflect.DeepEqual(after.guards[:len(before.guards)], before.guards) {
						t.Fatal("maintenance replaced an installed OAuth guard")
					}
					continue
				}
				if before.namespace != after.namespace || before.preflight != after.preflight ||
					!maps.Equal(before.owners, after.owners) || !reflect.DeepEqual(before.guards, after.guards) {
					t.Fatalf("maintenance changed existing history %q", before.namespace)
				}
				maintenanceEqualMigrations(t, after.history, before.history)
			}
		})
	}
}

func TestOAuthProxyMaintenanceExpansionCannotActivateCustodyWriters(t *testing.T) {
	for _, selection := range []struct {
		name       string
		kind       kernel.OAuthProxyRetirementKind
		custody    string
		fence      string
		fenceStart migrations.Version
		activation migrations.Version
	}{
		{name: "production", kind: kernel.OAuthProxyRetireProduction, custody: "proxy_transactions", fence: "proxy_production_write_fences", fenceStart: 7, activation: 10},
		{name: "preview", kind: kernel.OAuthProxyRetirePreview, custody: "proxy_preview_bindings", fence: "proxy_preview_write_fences", fenceStart: 6, activation: 8},
	} {
		t.Run(selection.name, func(t *testing.T) {
			const schema = "maintenance_oauth"
			expansion, expandGuards, err := proxyMaintenanceMigrationSuffix(t.Context(), schema, selection.kind, OAuthProxyMaintenanceExpand)
			if err != nil {
				t.Fatal(err)
			}
			activation, activeGuards, err := proxyMaintenanceMigrationSuffix(t.Context(), schema, selection.kind, OAuthProxyMaintenanceActivate)
			if err != nil || len(activation) != len(expansion)+1 || len(activeGuards) != len(expandGuards)+1 {
				t.Fatal("activation must append exactly one separately guarded step", err)
			}
			maintenanceEqualMigrations(t, activation[:len(expansion)], expansion)
			if !reflect.DeepEqual(activeGuards[:len(expandGuards)], expandGuards) {
				t.Fatal("activation changed expansion guards")
			}
			var sources []migrations.Source
			var wantGuards []migrationGuard
			if selection.kind == kernel.OAuthProxyRetireProduction {
				sources = append(sources, oauthpg.ProviderDisableCascadeMigrationSource{Schema: schema, Version: 6})
				wantGuards = append(wantGuards, migrationGuard{version: 6, schema: schema, tables: []string{"provider_disable_cascades"}})
			}
			sources = append(sources,
				oauthpg.ProxyCustodyWriteFenceMigrationSource{Schema: schema, Version: selection.fenceStart, Kind: selection.kind},
				oauthpg.ProxyRetirementDrainMigrationSource{Schema: schema, Version: selection.fenceStart + 1},
			)
			wantGuards = append(wantGuards,
				migrationGuard{version: selection.fenceStart, schema: schema, tables: []string{selection.fence},
					columns: []string{selection.custody + ".fence_provider_id", selection.custody + ".fence_provider_epoch"}},
				migrationGuard{version: selection.fenceStart + 1, schema: schema, tables: []string{"proxy_retirement_drains"}},
			)
			if selection.kind == kernel.OAuthProxyRetireProduction {
				sources = append(sources, oauthpg.ProxyDisablePairMigrationSource{Schema: schema, Version: 9})
				wantGuards = append(wantGuards, migrationGuard{version: 9, schema: schema, tables: []string{"provider_disable_proxy_pairs"}})
			}
			maintenanceEqualMigrations(t, expansion, maintenanceLoadSources(t, sources...))
			if !reflect.DeepEqual(expandGuards, wantGuards) {
				t.Fatal("expansion did not guard every newly owned table and custody column")
			}
			for _, step := range expansion {
				if step.DownSQL() != "" || step.TransactionMode() != migrations.TransactionModeDefault {
					t.Fatal("maintenance expansion lost its transactional, forward-only contract")
				}
				for _, forbidden := range []string{"CREATE FUNCTION", "CREATE CONSTRAINT TRIGGER", "INSERT INTO", "UPDATE ", "DELETE FROM", "GRANT "} {
					if strings.Contains(strings.ToUpper(step.UpSQL()), forbidden) {
						t.Fatalf("expansion version %d enables enforcement, changes existing data or changes runtime grants", step.Version())
					}
				}
			}
			last := activation[len(activation)-1]
			wantActivation := maintenanceLoadSources(t, oauthpg.ProxyCustodyWriteFenceActivationSource{
				Schema: schema, Version: selection.activation, Kind: selection.kind,
			})
			maintenanceEqualMigrations(t, []migrations.Migration{last}, wantActivation)
			if !strings.Contains(last.UpSQL(), "CREATE CONSTRAINT TRIGGER proxy_custody_write_fence AFTER INSERT ON \""+schema+"\"."+selection.custody) ||
				!strings.Contains(last.UpSQL(), "DEFERRABLE INITIALLY DEFERRED") {
				t.Fatal("activation did not enforce custody at transaction commit")
			}
			wantActivationGuard := migrationGuard{version: selection.activation, schema: schema,
				functions: []string{"enforce_proxy_" + selection.name + "_write_fence"}}
			if !reflect.DeepEqual(activeGuards[len(activeGuards)-1], wantActivationGuard) {
				t.Fatal("activation omitted the unmanaged enforcement-function guard")
			}
		})
	}
}

func TestOAuthProxyMaintenanceSuffixRejectsUnsupportedSelections(t *testing.T) {
	for _, selection := range []struct {
		name   string
		ctx    context.Context
		schema string
		kind   kernel.OAuthProxyRetirementKind
		phase  OAuthProxyMaintenanceSchema
	}{
		{name: "phase", ctx: t.Context(), schema: "maintenance_oauth", kind: kernel.OAuthProxyRetireProduction, phase: OAuthProxyMaintenanceSchema(255)},
		{name: "kind", ctx: t.Context(), schema: "maintenance_oauth", kind: kernel.OAuthProxyRetirementKind(255), phase: OAuthProxyMaintenanceExpand},
		{name: "schema", ctx: t.Context(), schema: "public", kind: kernel.OAuthProxyRetirePreview, phase: OAuthProxyMaintenanceActivate},
		{name: "nil-context", schema: "maintenance_oauth", kind: kernel.OAuthProxyRetireProduction, phase: OAuthProxyMaintenanceExpand},
	} {
		t.Run(selection.name, func(t *testing.T) {
			history, guards, err := proxyMaintenanceMigrationSuffix(selection.ctx, selection.schema, selection.kind, selection.phase)
			var invalid identity.InvalidInputError
			if !errors.As(err, &invalid) || len(history) != 0 || len(guards) != 0 {
				t.Fatal("invalid selection exposed a usable partial migration suffix", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	history, guards, err := proxyMaintenanceMigrationSuffix(ctx, "maintenance_oauth", kernel.OAuthProxyRetireProduction, OAuthProxyMaintenanceActivate)
	if !errors.Is(err, context.Canceled) || len(history) != 0 || len(guards) != 0 {
		t.Fatal("cancelled selection exposed a usable partial migration suffix", err)
	}
}

func TestOAuthProxyMaintenancePlanRequiresRecordedExpansionBeforeActivation(t *testing.T) {
	production, err := productionProxyMigrationCatalog(t.Context(), OAuthProxyProductionMigrationConfiguration{
		Schema: "production_oauth", GlobalAuthorityID: "synthetic-deployment", TenantID: "AAAAAAAAAAAAAAAAAAAAAQ",
	}, productionProxyMaintenanceActivate)
	if err != nil {
		t.Fatal(err)
	}
	previewStores := StoreSet{state: &storeState{
		config: VelocityStoreConfiguration{Schema: "preview_risk"}, proxyMaintenance: OAuthProxyMaintenanceActivate,
		features: &featureState{socialOAuth: &socialOAuthState{schema: "preview_oauth"}, oauthProxyPreview: &oauthProxyPreviewState{}},
	}}
	preview, err := previewStores.socialOAuthMigrationCatalog(t.Context(), []migrationHistory{production[0]})
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range []struct {
		name       string
		history    migrationHistory
		activation migrations.Version
	}{
		{name: "production", history: maintenanceHistory(t, production, "identity_oauth_proxy"), activation: 10},
		{name: "preview", history: maintenanceHistory(t, preview, "identity_social_oauth"), activation: 8},
	} {
		t.Run(selection.name, func(t *testing.T) {
			history := selection.history
			if history.activationBoundary != selection.activation {
				t.Fatal("activated catalog did not retain its separate planning boundary")
			}
			records := make([]migrations.Record, len(history.history)-1)
			for i, step := range history.history[:len(records)] {
				records[i], err = migrations.NewRecord(migrations.RecordKindMigration, step.Version(), step.Name(), step.Checksum(), time.Unix(1700000000, 0), time.Millisecond, false)
				if err != nil {
					t.Fatal(err)
				}
			}
			for _, recorded := range []int{0, 5, len(records) - 1, len(records)} {
				snapshot := migrationSnapshot{history: history, records: records[:recorded], statuses: history.project(records[:recorded])}
				plan, err := buildMigrationPlan([]migrationSnapshot{snapshot}, []ModuleID{"identity/oauth/postgres"})
				if recorded != len(records) {
					var conflict identity.ConflictError
					if !errors.As(err, &conflict) || plan.Digest != ([32]byte{}) || len(plan.Steps) != 0 {
						t.Fatalf("recorded prefix of %d steps allowed expansion and activation in one plan: %v", recorded, err)
					}
					continue
				}
				if err != nil || len(plan.Steps) != 1 || plan.Digest == ([32]byte{}) {
					t.Fatal("exact recorded expansion prefix did not produce a standalone activation plan", err)
				}
				step := plan.Steps[0]
				if step.Owner != "identity/oauth/postgres" || step.FromVersion != uint64(selection.activation-1) ||
					step.ToVersion != uint64(selection.activation) || !strings.HasSuffix(step.ID, "_write_fence_activation") ||
					step.SourceDigest != migrationSourceDigest(history) {
					t.Fatal("standalone plan lost the activation identity or exact expansion prefix binding")
				}
			}
		})
	}
}

func maintenanceHistory(t *testing.T, catalog []migrationHistory, namespace string) migrationHistory {
	t.Helper()
	index := slices.IndexFunc(catalog, func(h migrationHistory) bool { return h.namespace == namespace })
	if index < 0 {
		t.Fatalf("missing migration namespace %q", namespace)
	}
	return catalog[index]
}

func maintenanceLoadSources(t *testing.T, sources ...migrations.Source) []migrations.Migration {
	t.Helper()
	var history []migrations.Migration
	for _, source := range sources {
		steps, err := source.Load(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		history = append(history, steps...)
	}
	return history
}

func maintenanceEqualMigrations(t *testing.T, actual, expected []migrations.Migration) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("migration count %d, want %d", len(actual), len(expected))
	}
	for i, step := range actual {
		want := expected[i]
		if step.Version() != want.Version() || step.Name() != want.Name() || step.Checksum() != want.Checksum() ||
			step.UpSQL() != want.UpSQL() || step.DownSQL() != want.DownSQL() || step.TransactionMode() != want.TransactionMode() {
			t.Fatalf("migration %d changed native bytes, version or execution mode", want.Version())
		}
	}
}
