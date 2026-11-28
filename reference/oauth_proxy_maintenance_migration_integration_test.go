//go:build integration

package reference_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
)

func TestReferencePostgresOAuthProxyMaintenanceRequiresSeparateManagedActivation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false, true)
	_, production := oauthProxyProductionConfiguration(t)
	c := oauthProxyProductionMigrationConfiguration(production)
	retirement, err := reference.NewOAuthProxyProductionMigrationsWithRetirement(f.pool, c)
	if err != nil {
		t.Fatal("construct managed retirement predecessor", err)
	}
	cleanupOAuthProxyProductionMigrations(t, ctx, f, retirement)
	coldActivation, err := reference.NewOAuthProxyProductionMigrationsWithMaintenance(f.pool, c, reference.OAuthProxyMaintenanceActivate)
	if err != nil {
		t.Fatal("construct activation selection before expansion", err)
	}
	defer coldActivation.Close(ctx)
	var conflict identity.ConflictError
	if plan, err := coldActivation.Plan(ctx); !errors.As(err, &conflict) || len(plan.Plan.Steps) != 0 || plan.Plan.Digest != ([32]byte{}) {
		t.Fatal("cold activation selection planned expansion and enforcement together", err)
	}
	assertOAuthProxyProductionMigrationSchemaAbsent(t, ctx, f)
	predecessor, err := retirement.Plan(ctx)
	if err != nil || len(predecessor.Plan.Steps) == 0 {
		t.Fatal("plan managed retirement predecessor", err)
	}
	assertOAuthProxyProductionMigrationApply(t, ctx, retirement, oauthProxyProductionMigrationRequest(t, predecessor.Plan))
	assertOAuthProxyProductionMigrationsCompatible(t, ctx, retirement, len(predecessor.Plan.Modules))
	const originalHistory = `SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text
 FROM public.golib_migrations_identity_oauth_proxy m WHERE version<=5`
	var originalLedger string
	if err := f.pool.Raw().QueryRow(ctx, originalHistory).Scan(&originalLedger); err != nil {
		t.Fatal("snapshot managed retirement predecessor", err)
	}
	var originalCommands int
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*) FROM public.golib_migration_commands`).Scan(&originalCommands); err != nil {
		t.Fatal(err)
	}
	if plan, err := coldActivation.Plan(ctx); !errors.As(err, &conflict) || len(plan.Plan.Steps) != 0 || plan.Plan.Digest != ([32]byte{}) {
		t.Fatal("installed retirement prefix allowed activation before expansion", err)
	}
	var noMaintenanceWrites bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 to_regclass('synthetic_oauth.provider_disable_cascades') IS NULL AND
 to_regclass('synthetic_oauth.proxy_production_write_fences') IS NULL AND
 to_regclass('synthetic_oauth.proxy_retirement_drains') IS NULL AND
 to_regclass('synthetic_oauth.provider_disable_proxy_pairs') IS NULL AND
 NOT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid='synthetic_oauth.proxy_transactions'::regclass
 AND attname IN ('fence_provider_id','fence_provider_epoch') AND NOT attisdropped) AND
 NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='synthetic_oauth.proxy_transactions'::regclass
 AND tgname='proxy_custody_write_fence') AND
 (SELECT count(*) FROM public.golib_migration_commands)=$1`, originalCommands).Scan(&noMaintenanceWrites); err != nil || !noMaintenanceWrites {
		t.Fatal("rejected activation planning changed schema or managed commands", err)
	}
	expand, err := reference.NewOAuthProxyProductionMigrationsWithMaintenance(f.pool, c, reference.OAuthProxyMaintenanceExpand)
	if err != nil {
		t.Fatal("construct explicit expansion owner", err)
	}
	defer expand.Close(ctx)
	expansion, err := expand.Plan(ctx)
	if err != nil || len(expansion.Plan.Steps) != 4 {
		t.Fatal("expansion did not append exactly four managed migrations", err)
	}
	for i, step := range expansion.Plan.Steps {
		if step.Owner != "identity/oauth/postgres" || step.FromVersion != uint64(5+i) || step.ToVersion != uint64(6+i) {
			t.Fatal("expansion replanned a predecessor or included activation", step)
		}
	}
	expansionRequest := oauthProxyMaintenanceMigrationRequest(t, expansion.Plan, "expand")
	assertOAuthProxyMaintenanceSuffixApply(t, ctx, expand, expansionRequest, 9)
	assertOAuthProxyProductionMigrationsCompatible(t, ctx, expand, len(expansion.Plan.Modules))
	var expansionOnly bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT
 to_regclass('synthetic_oauth.provider_disable_cascades') IS NOT NULL AND
 to_regclass('synthetic_oauth.proxy_production_write_fences') IS NOT NULL AND
 to_regclass('synthetic_oauth.proxy_retirement_drains') IS NOT NULL AND
 to_regclass('synthetic_oauth.provider_disable_proxy_pairs') IS NOT NULL AND
 (SELECT count(*)=2 AND bool_and(NOT attnotnull) FROM pg_attribute
 WHERE attrelid='synthetic_oauth.proxy_transactions'::regclass
 AND attname IN ('fence_provider_id','fence_provider_epoch') AND NOT attisdropped) AND
 NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='synthetic_oauth.proxy_transactions'::regclass
 AND tgname='proxy_custody_write_fence') AND
 to_regprocedure('synthetic_oauth.enforce_proxy_production_write_fence()') IS NULL`).Scan(&expansionOnly); err != nil || !expansionOnly {
		t.Fatal("expansion omitted nullable storage or prematurely enforced custody writers", err)
	}
	const expandedHistory = `SELECT jsonb_agg(to_jsonb(m) ORDER BY version)::text
 FROM public.golib_migrations_identity_oauth_proxy m WHERE version<=9`
	var expandedLedger string
	if err := f.pool.Raw().QueryRow(ctx, expandedHistory).Scan(&expandedLedger); err != nil {
		t.Fatal("snapshot separately applied expansion", err)
	}
	activation, err := reference.NewOAuthProxyProductionMigrationsWithMaintenance(f.pool, c, reference.OAuthProxyMaintenanceActivate)
	if err != nil {
		t.Fatal("reconstruct activation owner after recorded expansion", err)
	}
	defer activation.Close(ctx)
	activationPlan, err := activation.Plan(ctx)
	if err != nil || len(activationPlan.Plan.Steps) != 1 {
		t.Fatal("recorded expansion did not permit one separate activation migration", err)
	}
	step := activationPlan.Plan.Steps[0]
	if step.Owner != "identity/oauth/postgres" || step.FromVersion != 9 || step.ToVersion != 10 {
		t.Fatal("separate activation changed the managed expansion prefix", step)
	}
	activationRequest := oauthProxyMaintenanceMigrationRequest(t, activationPlan.Plan, "activate")
	assertOAuthProxyMaintenanceSuffixApply(t, ctx, activation, activationRequest, 10)
	assertOAuthProxyProductionMigrationsCompatible(t, ctx, activation, len(activationPlan.Plan.Modules))
	var activeFence bool
	if err := f.pool.Raw().QueryRow(ctx, `SELECT count(*)=1 AND bool_and(
 t.tgenabled='O' AND t.tgdeferrable AND t.tginitdeferred AND t.tgconstraint<>0 AND
 t.tgfoid='synthetic_oauth.enforce_proxy_production_write_fence()'::regprocedure)
 FROM pg_trigger t WHERE t.tgrelid='synthetic_oauth.proxy_transactions'::regclass
 AND t.tgname='proxy_custody_write_fence' AND NOT t.tgisinternal`).Scan(&activeFence); err != nil || !activeFence {
		t.Fatal("activation did not install the enabled deferred native custody fence", err)
	}
	var retainedOriginal, retainedExpansion string
	if err := f.pool.Raw().QueryRow(ctx, originalHistory).Scan(&retainedOriginal); err != nil || retainedOriginal != originalLedger {
		t.Fatal("maintenance rewrote managed retirement predecessor records", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, expandedHistory).Scan(&retainedExpansion); err != nil || retainedExpansion != expandedLedger {
		t.Fatal("activation rewrote separately recorded expansion records", err)
	}
	noop, err := activation.Plan(ctx)
	if err != nil || len(noop.Plan.Steps) != 0 || noop.Plan.Digest == ([32]byte{}) {
		t.Fatal("separate activation did not leave a valid managed no-op plan", err)
	}
}

func oauthProxyMaintenanceMigrationRequest(t *testing.T, plan reference.MigrationPlan, phase string) reference.ReferenceMigrationApplyRequest {
	t.Helper()
	request := oauthProxyProductionMigrationRequest(t, plan)
	request.CommandID = identity.CommandID("production_proxy_maintenance_" + phase + "_0001")
	key, err := identity.NewIdempotencyKey([]byte("production-proxy-maintenance-" + phase))
	if err != nil {
		t.Fatal(err)
	}
	request.IdempotencyKey = key
	return request
}

func assertOAuthProxyMaintenanceSuffixApply(t *testing.T, ctx context.Context, owner reference.OAuthProxyProductionMigrations, request reference.ReferenceMigrationApplyRequest, version uint64) {
	t.Helper()
	for attempt := range 2 {
		result, err := owner.Apply(ctx, request)
		receipts := result.Result.Receipts()
		wantReceipt := reference.MigrationContributorReceipt{Module: "identity/oauth/postgres", Version: version}
		if err != nil || result.Result.State() != reference.MigrationApplied || result.Result.CommandID() != request.CommandID ||
			result.Result.Digest() != request.Plan.Digest || len(receipts) != 1 || receipts[0] != wantReceipt {
			t.Fatal("managed maintenance apply or exact replay lost its command, plan or native receipt", attempt, err)
		}
	}
}
