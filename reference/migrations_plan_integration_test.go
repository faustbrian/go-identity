//go:build integration

package reference_test

import (
	"context"
	"errors"
	"io/fs"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	outboxpg "github.com/faustbrian/go-transactional-outbox/v2/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestReferenceMigrationPlanNativeReadOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	role := pgx.Identifier{"plan_" + f.pool.Raw().Config().ConnConfig.Database}.Sanitize()
	if _, err := f.pool.Raw().Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(cleanup, "DROP OWNED BY "+role+"; DROP ROLE "+role); err != nil {
			t.Error(err)
		}
	})
	readPool, err := database.New(ctx, database.Config{DSN: f.pool.Raw().Config().ConnString(), MaxConns: 2, SessionInit: func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET SESSION AUTHORIZATION "+role)
		return err
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := readPool.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	if _, err := readPool.Raw().Exec(ctx, "CREATE TABLE public.forbidden_plan_write(id int)"); err == nil {
		t.Fatal("planner fixture principal can write")
	}
	stores, err := reference.ComposeStores(f.config, reference.ReferenceDependencies{PostgreSQL: readPool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := stores.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	request := reference.ReferenceMigrationPlanRequest{Modules: []reference.ModuleID{"identity/risk/postgres", "identity/postgres"}}
	result, err := stores.ReferenceMigrationPlan(ctx, request)
	if err != nil || result.Plan.Digest == ([32]byte{}) {
		t.Fatal("missing read-only native plan", err)
	}
	plan := result.Plan
	if len(plan.Steps) != 21 || !reflect.DeepEqual(plan.Modules, []reference.ModuleVersion{{Module: "identity/postgres"}, {Module: "identity/risk/postgres"}}) {
		t.Fatal("wrong empty-history plan", plan.Modules, len(plan.Steps))
	}
	history, err := f.stores.MigrationSource().Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	previous := map[reference.ModuleID]uint64{}
	for i, step := range plan.Steps {
		want := history[i]
		owner := reference.ModuleID("identity/postgres")
		if want.Version() >= 1000 {
			owner = "identity/risk/postgres"
		}
		if step.Owner != owner || step.ID != strconv.FormatUint(uint64(want.Version()), 10)+"_"+want.Name() || step.FromVersion != previous[owner] || step.ToVersion != uint64(want.Version()) || step.SourceDigest == ([32]byte{}) || step.StepDigest == ([32]byte{}) {
			t.Fatal("native step identity changed", step)
		}
		previous[owner] = step.ToVersion
	}
	request.Modules[0], request.Modules[1] = request.Modules[1], request.Modules[0]
	again, err := stores.ReferenceMigrationPlan(ctx, request)
	if err != nil || !reflect.DeepEqual(plan, again.Plan) || request.Modules[0] != "identity/postgres" {
		t.Fatal("request order changes canonical plan or was mutated", err)
	}
	again.Plan.Modules[0].Version = 9000
	again.Plan.Steps[0].ID = "changed"
	fresh, err := stores.ReferenceMigrationPlan(ctx, request)
	if err != nil || !reflect.DeepEqual(plan, fresh.Plan) {
		t.Fatal("caller mutation escaped into planner", err)
	}
	var absent bool
	if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass('public.migrations') IS NULL AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname IN('identity','risk_store'))").Scan(&absent); err != nil || !absent {
		t.Fatal("Plan prepared ledger/schema", err)
	}
	db := stdlib.OpenDBFromPool(f.pool.Raw())
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := backend.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := stores.ReferenceMigrationPlan(ctx, request); err != nil || !reflect.DeepEqual(plan, result.Plan) {
		t.Fatal("read-only plan needs apply ownership", err)
	}
	if err := lock.Release(ctx); err != nil {
		t.Fatal(err)
	}
	assertConflict := func(ids ...reference.ModuleID) {
		t.Helper()
		result, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: ids})
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || result.Plan.Digest != ([32]byte{}) {
			t.Fatal("unsafe history/selection produced a plan", result, err)
		}
	}
	assertConflict("identity/risk/postgres")
	runner, err := migrations.NewRunner(f.stores.MigrationSource(), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "GRANT SELECT ON public.migrations TO "+role); err != nil {
		t.Fatal(err)
	}
	complete, err := stores.ReferenceMigrationPlan(ctx, request)
	if err != nil || complete.Plan.Digest == ([32]byte{}) || len(complete.Plan.Steps) != 0 || complete.Plan.BaseLedgerDigest == plan.BaseLedgerDigest || complete.Plan.CatalogDigest != plan.CatalogDigest || complete.Plan.Modules[0].Version != 9 || complete.Plan.Modules[1].Version != 1011 {
		t.Fatal("installed native history is not a bound no-op plan", complete, err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE public.migrations SET dirty=true,finished_at=NULL WHERE version=1011"); err != nil {
		t.Fatal(err)
	}
	assertConflict("identity/postgres") // Dirty shared prerequisite is not hidden.
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE public.migrations SET dirty=false,finished_at=clock_timestamp(),checksum='sha256:'||repeat('1',64) WHERE version=1011"); err != nil {
		t.Fatal(err)
	}
	assertConflict("identity/postgres")
	for _, ids := range [][]reference.ModuleID{nil, {"identity/postgres", "identity/postgres"}, {"identity/otp/postgres"}, {"pkg/identity/postgres"}, {"unknown"}, {reference.ModuleID(string(make([]byte, 129)))}} {
		result, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: ids})
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) || result.Plan.Digest != ([32]byte{}) {
			t.Fatal("invalid plan selection accepted", err)
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if result, err := stores.ReferenceMigrationPlan(canceled, request); !errors.Is(err, context.Canceled) || result.Plan.Digest != ([32]byte{}) {
		t.Fatal("canceled plan returned authority", err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if result, err := stores.ReferenceMigrationPlan(ctx, request); err == nil || result.Plan.Digest != ([32]byte{}) {
		t.Fatal("closed owner planned migration")
	}
	if err := readPool.Raw().Ping(ctx); err != nil {
		t.Fatal("planner closed borrowed pool", err)
	}
}

func TestReferenceMigrationPlanFeaturePrerequisites(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	config, deps, _ := otpGraphConfiguration(t, f.config)
	deps.PostgreSQL = f.pool
	stores, err := reference.ComposeStores(config, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stores.Close(context.Background()) })
	ids := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity"}
	full, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: ids})
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Plan.Modules) != 9 {
		t.Fatal("missing selected owner")
	}
	// Shared physical order is kernel, risk, kernel, OTP, session, delivery,
	// authorization; independent histories follow in native dependency order.
	previous := map[reference.ModuleID]uint64{}
	seenNamespaces := map[reference.ModuleID]bool{}
	for _, step := range full.Plan.Steps {
		if step.FromVersion != previous[step.Owner] {
			t.Fatal("from-version belongs to another owner", step)
		}
		previous[step.Owner] = step.ToVersion
		if step.ToVersion == 1 {
			seenNamespaces[step.Owner] = true
		}
	}
	for _, owner := range []reference.ModuleID{"identity/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity"} {
		if !seenNamespaces[owner] {
			t.Fatal("overlapping original version was rewritten", owner)
		}
	}
	last := full.Plan.Steps[len(full.Plan.Steps)-1]
	if last.Owner != "outbox/postgres/identity" {
		t.Fatal("lifecycle prerequisite reordered")
	}
	conflict := func(ids ...reference.ModuleID) {
		t.Helper()
		result, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: ids})
		var e identity.ConflictError
		if !errors.As(err, &e) || result.Plan.Digest != ([32]byte{}) {
			t.Fatal("pending prerequisite accepted", err)
		}
	}
	conflict("identity/postgres")
	conflict("outbox/postgres/identity")
	db := stdlib.OpenDBFromPool(f.pool.Raw())
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	history, err := stores.MigrationSource().Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	prefix := migrationCheckPrefix{}
	for _, step := range history {
		if step.Version() <= 1011 {
			prefix = append(prefix, step)
		}
	}
	runner, err := migrations.NewRunner(prefix, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	partial, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: []reference.ModuleID{"identity/postgres"}})
	if err != nil || len(partial.Plan.Steps) != 7 || partial.Plan.Modules[0].Version != 9 {
		t.Fatal("completed prerequisite requires unselected later owners", partial, err)
	}
	for i, step := range partial.Plan.Steps {
		if step.Owner != "identity/postgres" || step.ToVersion != uint64(1012+i) {
			t.Fatal("unselected future migrations added", step)
		}
	}
	// Install only the real root-outbox source in its independent namespace.
	source, err := migrations.NewFSSource(fixtureMigrationFiles{fs.FS(outboxpg.Migrations())}, ".")
	if err != nil {
		t.Fatal(err)
	}
	rootHistory, err := source.Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	root, err := backend.ForNamespace("outbox")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.InstallFresh(ctx, rootHistory, ""); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: []reference.ModuleID{"outbox/postgres/identity"}})
	if err != nil || len(lifecycle.Plan.Steps) == 0 {
		t.Fatal("completed root prerequisite rejected", err)
	}
	for _, step := range lifecycle.Plan.Steps {
		if step.Owner != "outbox/postgres/identity" {
			t.Fatal("implicit root work")
		}
	}
	// Concurrent operations own independent snapshots and produce the same plan.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			result, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: []reference.ModuleID{"identity/postgres"}})
			if err != nil || !reflect.DeepEqual(result.Plan, partial.Plan) {
				t.Error("concurrent plan drift", err)
			}
		})
	}
	wg.Wait()
	// Request sorting and native physical ordering remain independent.
	slices.Reverse(ids)
	after, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: ids})
	if err != nil || after.Plan.CatalogDigest != full.Plan.CatalogDigest || after.Plan.BaseLedgerDigest == full.Plan.BaseLedgerDigest {
		t.Fatal("catalog or base identity lost", err)
	}
}

func TestReferenceMigrationPlanCancellationDrains(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	f := newLiveStores(t, ctx)
	request := reference.ReferenceMigrationPlanRequest{Modules: []reference.ModuleID{"identity/postgres"}}
	tx, err := f.pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err := tx.Exec(ctx, "LOCK TABLE public.migrations IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal(err)
	}
	deadline, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	_, err = f.stores.ReferenceMigrationPlan(deadline, request)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked ledger ignored deadline", err)
	}
	finished := make(chan error, 1)
	go func() {
		_, err := f.stores.ReferenceMigrationPlan(ctx, request)
		finished <- err
	}()
	// Observe the actual blocked PostgreSQL query before closing the store;
	// scheduling alone cannot prove that Close cancels an admitted operation.
	observed, end := context.WithTimeout(ctx, 2*time.Second)
	defer end()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := f.pool.Raw().QueryRow(observed, "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock')").Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case <-observed.Done():
			t.Fatal("planner did not reach ledger read")
		case <-ticker.C:
		}
	}
	if err := f.stores.Close(ctx); err != nil {
		t.Fatal("store failed to drain blocked planner", err)
	}
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("shutdown cancellation lost", err)
		}
	case <-ctx.Done():
		t.Fatal("planner leaked after Close")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.Raw().Ping(ctx); err != nil {
		t.Fatal("borrowed pool closed", err)
	}
}
