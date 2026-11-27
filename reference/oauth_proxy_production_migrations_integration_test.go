//go:build integration

package reference_test

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
)

func oauthProxyProductionMigrationConfiguration(c reference.OAuthProxyProductionConfiguration) reference.OAuthProxyProductionMigrationConfiguration {
	return reference.OAuthProxyProductionMigrationConfiguration{
		Schema: c.Native.Schema, GlobalAuthorityID: c.Native.GlobalAuthorityID,
		TenantID: c.Start.Preview.TenantID, Timeout: 15 * time.Second,
		Apply: &reference.MigrationApplyPolicy{
			TenantID: "deployment", ActorID: "operator", LookupKey: [32]byte{8},
			LockTimeout: time.Second, CleanupTimeout: time.Second,
		},
	}
}

func applyOAuthProxyProductionMigrations(t *testing.T, ctx context.Context, f liveStores, c reference.OAuthProxyProductionConfiguration) {
	t.Helper()
	configuration := oauthProxyProductionMigrationConfiguration(c)
	configuration.HTTPRiskSchema = "risk_store"
	owner, err := reference.NewOAuthProxyProductionMigrations(f.pool, configuration)
	if err != nil {
		t.Fatal("construct public production migration owner", err)
	}
	cleanupOAuthProxyProductionMigrations(t, ctx, f, owner)
	before, err := owner.Check(ctx)
	if err != nil || len(before.Statuses) == 0 {
		t.Fatal("check fresh public production migrations", err)
	}
	for _, status := range before.Statuses {
		if status.Compatibility != reference.MigrationRequired || status.CurrentVersion != 0 {
			t.Fatal("fresh public production owner was not migration-required", status.Module)
		}
	}
	planned, err := owner.Plan(ctx)
	if err != nil || len(planned.Plan.Steps) == 0 {
		t.Fatal("plan fresh public production migrations", err)
	}
	var riskSelected, rateSelected bool
	for _, module := range planned.Plan.Modules {
		riskSelected = riskSelected || module.Module == "identity/risk/postgres"
		rateSelected = rateSelected || module.Module == "rate-limit/postgres"
	}
	if !riskSelected || !rateSelected {
		t.Fatal("production HTTP bootstrap omitted its durable risk or rate owner")
	}
	assertOAuthProxyProductionMigrationSchemaAbsent(t, ctx, f)
	request := oauthProxyProductionMigrationRequest(t, planned.Plan)
	assertOAuthProxyProductionMigrationApply(t, ctx, owner, request)
	assertOAuthProxyProductionMigrationsCompatible(t, ctx, owner, len(planned.Plan.Modules))
	reconstructed, err := reference.NewOAuthProxyProductionMigrations(f.pool, configuration)
	if err != nil {
		t.Fatal("reconstruct public production migration owner", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := reconstructed.Close(bounded); err != nil {
			t.Error("close reconstructed production migration owner", err)
		}
	})
	assertOAuthProxyProductionMigrationApply(t, ctx, reconstructed, request)
	noop, err := reconstructed.Plan(ctx)
	if err != nil || len(noop.Plan.Steps) != 0 || noop.Plan.Digest == [32]byte{} {
		t.Fatal("completed public production migration plan was not a valid no-op", err)
	}
}

func TestReferencePostgresOAuthProxyProductionMigrationsNativeOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	_, production := oauthProxyProductionConfiguration(t)
	configuration := oauthProxyProductionMigrationConfiguration(production)
	disabled := configuration
	disabled.Apply = nil
	readOnly, err := reference.NewOAuthProxyProductionMigrations(f.pool, disabled)
	if err != nil {
		t.Fatal("construct read-only native production migrations", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := readOnly.Close(bounded); err != nil {
			t.Error("close read-only production migration owner", err)
		}
	})
	checked, err := readOnly.Check(ctx)
	if err != nil || len(checked.Statuses) == 0 {
		t.Fatal("check native-only production migrations without apply authority", err)
	}
	for _, status := range checked.Statuses {
		if status.Compatibility != reference.MigrationRequired || status.CurrentVersion != 0 {
			t.Fatal("native-only fresh migration owner was not required", status.Module)
		}
	}
	planned, err := readOnly.Plan(ctx)
	if err != nil || len(planned.Plan.Steps) == 0 {
		t.Fatal("plan native-only production migrations without apply authority", err)
	}
	for _, module := range planned.Plan.Modules {
		switch module.Module {
		case "identity/risk/postgres", "rate-limit/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "identity/password/postgres", "identity/mfa/postgres", "authorization/postgres":
			t.Fatal("native proxy selected an unrelated migration owner", module.Module)
		}
	}
	assertOAuthProxyProductionMigrationSchemaAbsent(t, ctx, f)
	request := oauthProxyProductionMigrationRequest(t, planned.Plan)
	if _, err := readOnly.Apply(ctx, request); err == nil {
		t.Fatal("native production migrations applied without explicit policy")
	}
	assertOAuthProxyProductionMigrationSchemaAbsent(t, ctx, f)
	owner, err := reference.NewOAuthProxyProductionMigrations(f.pool, configuration)
	if err != nil {
		t.Fatal("construct opted-in native production migration owner", err)
	}
	cleanupOAuthProxyProductionMigrations(t, ctx, f, owner)
	partial := request
	partial.Plan.Modules = partial.Plan.Modules[:len(partial.Plan.Modules)-1]
	if _, err := owner.Apply(ctx, partial); err == nil {
		t.Fatal("partial plan passed the complete production bootstrap boundary")
	}
	assertOAuthProxyProductionMigrationSchemaAbsent(t, ctx, f)
	assertOAuthProxyProductionMigrationApply(t, ctx, owner, request)
	assertOAuthProxyProductionMigrationsCompatible(t, ctx, owner, len(planned.Plan.Modules))
	var unrelatedAbsent bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 to_regnamespace('risk_store') IS NULL AND to_regnamespace('otp_store') IS NULL AND
 to_regnamespace('session_store') IS NULL AND to_regclass('public.rate_limit_states') IS NULL AND
 to_regclass('identity.accounts') IS NULL AND to_regclass('public.authorization_subject_authorities') IS NULL`).Scan(&unrelatedAbsent); err != nil || !unrelatedAbsent {
		t.Fatal("native-only production migration installed unselected owners", err)
	}
	if err := owner.Close(ctx); err != nil {
		t.Fatal("close native-only production migration owner", err)
	}
	if _, err := owner.Check(ctx); err == nil {
		t.Fatal("closed native-only production migration owner remained usable")
	}
	if err := f.pool.Raw().Ping(ctx); err != nil {
		t.Fatal("native-only production migration owner closed the borrowed pool", err)
	}
}

func oauthProxyProductionMigrationRequest(t *testing.T, plan reference.MigrationPlan) reference.ReferenceMigrationApplyRequest {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte("production-proxy-migration-retry"))
	if err != nil {
		t.Fatal(err)
	}
	return reference.ReferenceMigrationApplyRequest{CommandID: "production_proxy_migrations_0001", Plan: plan, IdempotencyKey: key}
}

func assertOAuthProxyProductionMigrationApply(t *testing.T, ctx context.Context, owner reference.OAuthProxyProductionMigrations, request reference.ReferenceMigrationApplyRequest) {
	t.Helper()
	result, err := owner.Apply(ctx, request)
	if err != nil || result.Result.State() != reference.MigrationApplied || result.Result.CommandID() != request.CommandID || result.Result.Digest() != request.Plan.Digest || len(result.Result.Receipts()) != len(request.Plan.Modules) {
		t.Fatal("public production migrations did not preserve complete applied command", err)
	}
}

func assertOAuthProxyProductionMigrationsCompatible(t *testing.T, ctx context.Context, owner reference.OAuthProxyProductionMigrations, modules int) {
	t.Helper()
	checked, err := owner.Check(ctx)
	if err != nil || len(checked.Statuses) != modules {
		t.Fatal("check completed public production migration owners", err)
	}
	for _, status := range checked.Statuses {
		if status.Compatibility != reference.MigrationCompatible || status.CurrentVersion != status.RequiredVersion {
			t.Fatal("completed public production migration owner is not compatible", status.Module)
		}
	}
}

func assertOAuthProxyProductionMigrationSchemaAbsent(t *testing.T, ctx context.Context, f liveStores) {
	t.Helper()
	var absent bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 to_regnamespace('identity') IS NULL AND to_regnamespace('synthetic_oauth') IS NULL AND
 to_regnamespace('audit') IS NULL AND to_regnamespace('risk_store') IS NULL AND
 to_regclass('public.migrations') IS NULL AND to_regclass('public.golib_migration_commands') IS NULL AND
 to_regclass('public.capability_identity_one_use') IS NULL AND to_regclass('public.rate_limit_states') IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal("public production construction, check, plan or rejected apply wrote schema", err)
	}
}

func cleanupOAuthProxyProductionMigrations(t *testing.T, ctx context.Context, f liveStores, owner reference.OAuthProxyProductionMigrations) {
	t.Helper()
	var roles int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_roles WHERE rolname IN ('audit_writer','audit_reader','audit_retention')`).Scan(&roles); err != nil || roles != 0 {
		t.Fatal("fresh standalone production fixture requires unclaimed audit roles", err)
	}
	t.Cleanup(func() {
		bounded, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := owner.Close(bounded); err != nil {
			t.Error("close public production migration owner", err)
		}
		if _, err := f.pool.Raw().Exec(bounded, `DO $$ DECLARE owned_role text; BEGIN
 FOREACH owned_role IN ARRAY ARRAY['audit_writer','audit_reader','audit_retention'] LOOP
 IF EXISTS (SELECT FROM pg_roles WHERE rolname=owned_role) THEN
 EXECUTE format('DROP OWNED BY %I',owned_role); EXECUTE format('DROP ROLE %I',owned_role);
 END IF; END LOOP; END $$`); err != nil {
			t.Error("release standalone production migration audit roles", err)
		}
	})
}
