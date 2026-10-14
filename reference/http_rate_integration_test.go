//go:build integration

package reference_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/reference"
	ratepg "github.com/faustbrian/go-rate-limit/v2/postgres"
)

// The production StoreSet supplies and applies the native contributor; no test
// SQL installs rate state. Direct native validation is an independent consumer
// oracle, not a substitute reference-server construction graph.
func TestReferenceHTTPRateNativeMigrationUsesGraphOwnership(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	c := f.config
	c.HTTPRate = &reference.HTTPRateConfiguration{Namespace: "reference-native", IdentifierKey: [32]byte{1}, MaximumDuration: time.Second, Timeout: 500 * time.Millisecond, LockTimeout: 250 * time.Millisecond, RollbackTimeout: 250 * time.Millisecond}
	c.Migrations = &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "operator", LookupKey: [32]byte{8}, LockTimeout: time.Second, CleanupTimeout: time.Second}
	c.Velocity.PrimaryTimeout = 10 * time.Second
	stores, err := reference.ComposeStores(c, reference.ReferenceDependencies{PostgreSQL: f.pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	ids := []reference.ModuleID{"rate-limit/postgres"}
	before, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: ids})
	if err != nil || len(before.Statuses) != 1 || before.Statuses[0].Compatibility != reference.MigrationRequired {
		t.Fatal("selected absent contributor", err)
	}
	request := applyRequest(t, ctx, stores, ids)
	if len(request.Plan.Steps) != 1 || request.Plan.Steps[0].Owner != ids[0] || request.Plan.Steps[0].ToVersion != 1 {
		t.Fatal("native independent plan lost ownership")
	}
	var untouched bool
	if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass('public.rate_limit_states') IS NULL AND to_regclass('public.migrations') IS NULL").Scan(&untouched); err != nil || !untouched {
		t.Fatal("construction/check/plan wrote schema", err)
	}
	applied, err := stores.ReferenceMigrationApply(ctx, request)
	if err != nil || applied.Result.State() != reference.MigrationApplied || len(applied.Result.Receipts()) != 1 || applied.Result.Receipts()[0].Module != ids[0] {
		t.Fatal("native selected apply", err)
	}
	backend, err := ratepg.OpenStrict(ctx, f.pool.Raw(), ratepg.StrictOptions{Options: ratepg.Options{Timeout: time.Second, LockTimeout: time.Second, Clock: ratepg.ServerClock}, RollbackTimeout: time.Second})
	if err != nil || backend == nil {
		t.Fatal("native schema consumer cannot validate", err)
	}
	after, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: ids})
	if err != nil || len(after.Statuses) != 1 || after.Statuses[0].Compatibility != reference.MigrationCompatible || after.Statuses[0].CurrentVersion != 1 {
		t.Fatal("native selected check after apply", err)
	}
	replay, err := stores.ReferenceMigrationApply(ctx, request)
	if err != nil || replay.Result.State() != reference.MigrationApplied {
		t.Fatal("native selected command replay", err)
	}
	if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass('public.migrations') IS NULL AND to_regclass('identity.users') IS NULL").Scan(&untouched); err != nil || !untouched {
		t.Fatal("rate-only apply installed unrelated authority", err)
	}
	if _, err := f.stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: ids}); err == nil {
		t.Fatal("disabled graph advertised contributor")
	}
	// Independent transport consumers validate the native SQL contract installed
	// by the graph. They are not a substitute for the forthcoming graph-owned
	// server/handler; their fresh in-memory owners must not reset durable budgets.
	consumers := make([]*identityhttp.AuthRateLimiter, 2)
	for i := range consumers {
		consumers[i], err = identityhttp.NewAuthRateLimiter(identityhttp.AuthRateConfig{Shared: backend, Namespace: c.HTTPRate.Namespace, IdentifierKey: c.HTTPRate.IdentifierKey, Now: time.Now, MaximumDuration: c.HTTPRate.MaximumDuration})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := consumers[i].Close(); err != nil {
				t.Error(err)
			}
		})
	}
	network, err := identityhttp.NewNetworkResolver(identityhttp.NetworkConfig{Limits: identityhttp.Limits{MaximumHeaderBytes: 8192, MaximumURLBytes: 1024, MaximumBodyBytes: 1024, MaximumDecodedBytes: 1024, MaximumFields: 32, MaximumDepth: 4}, MaximumForwardedHops: 1, TenantHosts: []identityhttp.TenantHost{{Host: "login.example", TenantID: "tenant"}}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://login.example/flow", nil)
	r.RequestURI = "/flow"
	r.RemoteAddr = "127.0.0.1:1234"
	facts, err := network.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 21; i++ {
		out, err := consumers[i%2].AdmitOriginalFlow(ctx, facts)
		if i < 20 && (err != nil || !out.Allowed) || i == 20 && (!errors.Is(err, identityhttp.ErrRateLimited) || out.Allowed || out.RetryAfter <= 0) {
			t.Fatal("independent native HTTP budget", i, err)
		}
	}
	// Only this task-owned database is damaged. Absence of authoritative schema
	// must deny even a new IP; no process-local healthy fallback is admissible.
	if _, err := f.pool.Raw().Exec(ctx, "DROP TABLE public.rate_limit_states"); err != nil {
		t.Fatal(err)
	}
	r.RemoteAddr = "127.0.0.2:1234"
	facts, err = network.Resolve(r)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := consumers[0].AdmitOriginalFlow(ctx, facts); err == nil || out.Allowed {
		t.Fatal("native storage outage allowed request")
	}
}
