//go:build integration

package reference_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	oauthpg "github.com/faustbrian/go-identity/oauth/postgres"
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

func TestReferencePostgresOAuthProxyProductionMigrationsAppendLiveAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	_, production := oauthProxyProductionConfiguration(t)
	c := oauthProxyProductionMigrationConfiguration(production)
	static, err := reference.NewOAuthProxyProductionMigrations(f.pool, c)
	if err != nil {
		t.Fatal("construct static production migration owner", err)
	}
	cleanupOAuthProxyProductionMigrations(t, ctx, f, static)
	base, err := static.Plan(ctx)
	if err != nil || len(base.Plan.Steps) == 0 {
		t.Fatal("plan static production migration history", err)
	}
	assertOAuthProxyProductionMigrationApply(t, ctx, static, oauthProxyProductionMigrationRequest(t, base.Plan))
	live, err := reference.NewOAuthProxyProductionMigrationsWithProviderAuthority(f.pool, c)
	if err != nil {
		t.Fatal("select live authority history for the existing production database", err)
	}
	defer live.Close(ctx)
	plan, err := live.Plan(ctx)
	if err != nil || len(plan.Plan.Steps) != 1 {
		t.Fatal("plan did not preserve the installed history and append exactly one migration", err)
	}
	step := plan.Plan.Steps[0]
	if step.Owner != "identity/oauth/postgres" || step.FromVersion != 2 || step.ToVersion != 3 {
		t.Fatal("unexpected OAuth authority migration owner or version", step.Owner, step.FromVersion, step.ToVersion)
	}
	var absent bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT to_regclass('synthetic_oauth.provider_authorities') IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal("the original profile or live planning created the authority table", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("production-proxy-authority-migration"))
	if err != nil {
		t.Fatal(err)
	}
	request := reference.ReferenceMigrationApplyRequest{CommandID: "production_proxy_migrations_authority_0001", Plan: plan.Plan, IdempotencyKey: key}
	for attempt := range 2 {
		result, err := live.Apply(ctx, request)
		wantReceipt := reference.MigrationContributorReceipt{Module: "identity/oauth/postgres", Version: 3}
		receipts := result.Result.Receipts()
		if err != nil || result.Result.State() != reference.MigrationApplied || result.Result.CommandID() != request.CommandID ||
			result.Result.Digest() != plan.Plan.Digest || len(receipts) != 1 || receipts[0] != wantReceipt {
			t.Fatal("incorrect migration attribution across apply and exact replay", attempt, result.Result.State(), receipts, err)
		}
	}
	assertOAuthProxyProductionMigrationsCompatible(t, ctx, live, len(plan.Plan.Modules))
	reader, err := oauthpg.NewProviderAuthority(f.pool, c.Schema, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	state, err := reader.Current(ctx, oauthpg.ProviderAuthorityKey{TenantID: c.TenantID, ProviderID: production.Start.Provider.Profile().ID})
	var denied identity.ForbiddenError
	if state != (oauthpg.ProviderAuthorityState{}) || !errors.As(err, &denied) {
		t.Fatal("bootstrapping live authority implicitly registered a provider", err)
	}
}

func TestReferencePostgresOAuthProxyProductionMigrationsAppendRetirement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	_, production := oauthProxyProductionConfiguration(t)
	c := oauthProxyProductionMigrationConfiguration(production)
	static, err := reference.NewOAuthProxyProductionMigrations(f.pool, c)
	if err != nil {
		t.Fatal("construct unchanged static production migration owner", err)
	}
	cleanupOAuthProxyProductionMigrations(t, ctx, f, static)
	staticPlan, err := static.Plan(ctx)
	if err != nil || len(staticPlan.Plan.Steps) == 0 {
		t.Fatal("plan unchanged static production migrations", err)
	}
	for _, step := range staticPlan.Plan.Steps {
		if step.Owner == "identity/oauth/postgres" && step.ToVersion > 2 {
			t.Fatal("default static profile opted into later OAuth history", step.ToVersion)
		}
	}
	live, err := reference.NewOAuthProxyProductionMigrationsWithProviderAuthority(f.pool, c)
	if err != nil {
		t.Fatal("construct installed live production migration owner", err)
	}
	defer live.Close(ctx)
	base, err := live.Plan(ctx)
	if err != nil || len(base.Plan.Steps) == 0 {
		t.Fatal("plan installed live production history", err)
	}
	for _, step := range base.Plan.Steps {
		if step.Owner == "identity/oauth/postgres" && step.ToVersion > 3 {
			t.Fatal("default live profile opted into retirement", step.ToVersion)
		}
	}
	assertOAuthProxyProductionMigrationSchemaAbsent(t, ctx, f)
	assertOAuthProxyProductionMigrationApply(t, ctx, live, oauthProxyProductionMigrationRequest(t, base.Plan))
	assertOAuthProxyProductionMigrationsCompatible(t, ctx, live, len(base.Plan.Modules))
	var originalLedger string
	const originalHistory = `SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text
 FROM public.golib_migrations_identity_oauth_proxy m WHERE version<=3`
	if err := f.pool.Raw().QueryRow(ctx, originalHistory).Scan(&originalLedger); err != nil {
		t.Fatal("snapshot authenticated installed OAuth migration history", err)
	}
	var retirementAbsent bool
	const noRetirementSchema = `SELECT NOT EXISTS (
 SELECT 1 FROM pg_attribute WHERE attrelid='synthetic_oauth.proxy_transactions'::regclass
 AND attname IN ('retirement_source_command_id','retirement_source_version','retired_at') AND NOT attisdropped)
 AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='synthetic_oauth.proxy_transactions'::regclass
 AND conname='proxy_transactions_retirement_shape')`
	if err := f.pool.Raw().QueryRow(ctx, noRetirementSchema).Scan(&retirementAbsent); err != nil || !retirementAbsent {
		t.Fatal("default live migration apply created opt-in retirement schema", err)
	}

	retirement, err := reference.NewOAuthProxyProductionMigrationsWithRetirement(f.pool, c)
	if err != nil {
		t.Fatal("select retirement history for the installed live production database", err)
	}
	defer retirement.Close(ctx)
	plan, err := retirement.Plan(ctx)
	if err != nil || len(plan.Plan.Steps) != 2 {
		t.Fatal("retirement plan did not append exactly two migrations", err)
	}
	for i, step := range plan.Plan.Steps {
		if step.Owner != "identity/oauth/postgres" || step.FromVersion != uint64(3+i) || step.ToVersion != uint64(4+i) {
			t.Fatal("retirement plan changed an unrelated owner or installed version", step)
		}
	}
	if err := f.pool.Raw().QueryRow(ctx, noRetirementSchema).Scan(&retirementAbsent); err != nil || !retirementAbsent {
		t.Fatal("retirement selection or planning installed schema before operator apply", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("production-proxy-retirement-migration"))
	if err != nil {
		t.Fatal(err)
	}
	request := reference.ReferenceMigrationApplyRequest{CommandID: "production_proxy_migrations_retirement_0001", Plan: plan.Plan, IdempotencyKey: key}
	for attempt := range 2 {
		result, err := retirement.Apply(ctx, request)
		receipts := result.Result.Receipts()
		wantReceipt := reference.MigrationContributorReceipt{Module: "identity/oauth/postgres", Version: 5}
		if err != nil || result.Result.State() != reference.MigrationApplied || result.Result.CommandID() != request.CommandID ||
			result.Result.Digest() != request.Plan.Digest || len(receipts) != 1 || receipts[0] != wantReceipt {
			t.Fatal("retirement apply or exact replay lost its original command and latest receipt", attempt, receipts, err)
		}
	}
	var retainedLedger string
	if err := f.pool.Raw().QueryRow(ctx, originalHistory).Scan(&retainedLedger); err != nil || retainedLedger != originalLedger {
		t.Fatal("retirement upgrade changed authenticated predecessor migration records", err)
	}
	var latestSchema bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 (SELECT count(*)=3 AND bool_and(NOT attnotnull) FROM pg_attribute
 WHERE attrelid='synthetic_oauth.proxy_transactions'::regclass AND NOT attisdropped AND
 ((attname='retirement_source_command_id' AND atttypid='bytea'::regtype) OR
  (attname='retirement_source_version' AND atttypid='numeric'::regtype) OR
  (attname='retired_at' AND atttypid='timestamptz'::regtype)))
 AND EXISTS (SELECT 1 FROM pg_constraint
 WHERE conrelid='synthetic_oauth.proxy_transactions'::regclass
 AND conname='proxy_transactions_retirement_shape' AND contype='c' AND convalidated)`).Scan(&latestSchema); err != nil || !latestSchema {
		t.Fatal("retirement upgrade omitted explicit columns or validated custody constraint", err)
	}
	assertOAuthProxyProductionMigrationsCompatible(t, ctx, retirement, len(plan.Plan.Modules))
	noop, err := retirement.Plan(ctx)
	if err != nil || len(noop.Plan.Steps) != 0 || noop.Plan.Digest == [32]byte{} {
		t.Fatal("retirement replay did not leave a valid no-op migration plan", err)
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
