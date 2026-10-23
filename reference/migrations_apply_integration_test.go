//go:build integration

package reference_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestReferenceMigrationApplyNativeExactPlanAndReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	f.config.Migrations = &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "operator", LookupKey: [32]byte{8}, LockTimeout: time.Second, CleanupTimeout: time.Second}
	f.config.Velocity.PrimaryTimeout = 10 * time.Second
	stores, err := reference.ComposeStores(f.config, reference.ReferenceDependencies{PostgreSQL: f.pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = stores.Close(cleanup)
	})
	planned, err := stores.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: []reference.ModuleID{"identity/postgres", "identity/risk/postgres"}})
	if err != nil {
		t.Fatal(err)
	}
	key, err := identity.NewIdempotencyKey([]byte("apply-original-retry-key"))
	if err != nil {
		t.Fatal(err)
	}
	req := reference.ReferenceMigrationApplyRequest{CommandID: "migration_command_0001", Plan: planned.Plan, IdempotencyKey: key}
	// Alter an independently bound component before any write.
	changed := req
	changed.Plan.CatalogDigest[0]++
	if _, err := stores.ReferenceMigrationApply(ctx, changed); err == nil {
		t.Fatal("altered plan accepted")
	}
	var untouched bool
	if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass('public.migrations') IS NULL AND to_regclass('public.golib_migration_commands') IS NULL").Scan(&untouched); err != nil || !untouched {
		t.Fatal("invalid plan prepared authority", err)
	}
	result, err := stores.ReferenceMigrationApply(ctx, req)
	if err != nil || result.Result.State() != reference.MigrationApplied || result.Result.CommandID() != req.CommandID || result.Result.Digest() != planned.Plan.Digest || len(result.Result.Receipts()) != 2 {
		t.Fatal("exact native plan did not apply", err)
	}
	db := stdlib.OpenDBFromPool(f.pool.Raw())
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	records, err := backend.ReadLedger(ctx)
	if err != nil || len(records) != len(planned.Plan.Steps) {
		t.Fatal("missing original native history", err)
	}
	source, err := stores.MigrationSource().Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, record := range records {
		if record.Kind() != migrations.RecordKindMigration || record.Version() != source[i].Version() || record.Checksum() != source[i].Checksum() || record.Name() != source[i].Name() || record.Dirty() {
			t.Fatal("native identity changed")
		}
	}
	// Reconstruct the owner: replay cannot depend on an in-memory receipt.
	reconstructed, err := reference.ComposeStores(f.config, reference.ReferenceDependencies{PostgreSQL: f.pool})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = reconstructed.Close(cleanup)
	}()
	replay, err := reconstructed.ReferenceMigrationApply(ctx, req)
	if err != nil || replay.Result.State() != reference.MigrationApplied || len(replay.Result.Receipts()) != 2 {
		t.Fatal("durable exact replay failed", err)
	}
	changed = req
	changed.CommandID = "migration_command_0002"
	if _, err := reconstructed.ReferenceMigrationApply(ctx, changed); err == nil {
		t.Fatal("foreign command adopted completed prefix")
	}
	key2, err := identity.NewIdempotencyKey([]byte("apply-different-key"))
	if err != nil {
		t.Fatal(err)
	}
	changed = req
	changed.IdempotencyKey = key2
	var conflict identity.ConflictError
	if _, err := reconstructed.ReferenceMigrationApply(ctx, changed); !errors.As(err, &conflict) {
		t.Fatal("same command rebound retry key", err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.ReferenceMigrationApply(ctx, req); err == nil {
		t.Fatal("closed owner applied")
	}
	if err := f.pool.Raw().Ping(ctx); err != nil {
		t.Fatal("borrowed pool closed", err)
	}
}

func applyProfile(t *testing.T, f liveStores) reference.StoreSet {
	t.Helper()
	f.config.Migrations = &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "operator", LookupKey: [32]byte{8}, LockTimeout: time.Second, CleanupTimeout: time.Second}
	f.config.Velocity.PrimaryTimeout = 10 * time.Second
	s, err := reference.ComposeStores(f.config, reference.ReferenceDependencies{PostgreSQL: f.pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	return s
}

func applyRequest(t *testing.T, ctx context.Context, s reference.StoreSet, ids []reference.ModuleID) reference.ReferenceMigrationApplyRequest {
	t.Helper()
	planned, err := s.ReferenceMigrationPlan(ctx, reference.ReferenceMigrationPlanRequest{Modules: ids})
	if err != nil {
		t.Fatal("selected native migration plan", err)
	}
	key, err := identity.NewIdempotencyKey([]byte("apply-original-retry-key"))
	if err != nil {
		t.Fatal(err)
	}
	return reference.ReferenceMigrationApplyRequest{CommandID: "migration_command_0001", Plan: planned.Plan, IdempotencyKey: key}
}

// Independently encode the documented plan so that forged, internally valid
// plans exercise authoritative equality rather than just the digest guard.
func rehashApplyPlan(p reference.MigrationPlan) reference.MigrationPlan {
	var wire bytes.Buffer
	number := func(n uint64) { _ = binary.Write(&wire, binary.BigEndian, n) }
	text := func(s string) { number(uint64(len(s))); wire.WriteString(s) }
	text("golib/reference/migrations/v1/plan")
	wire.Write(p.BaseLedgerDigest[:])
	wire.Write(p.CatalogDigest[:])
	number(uint64(len(p.Modules)))
	for _, m := range p.Modules {
		text(m.Module)
		number(m.Version)
	}
	number(uint64(len(p.Steps)))
	for _, s := range p.Steps {
		text(string(s.Owner))
		text(s.ID)
		number(s.FromVersion)
		number(s.ToVersion)
		wire.Write(s.SourceDigest[:])
		wire.Write(s.StepDigest[:])
	}
	p.Digest = sha256.Sum256(wire.Bytes())
	return p
}

func TestReferenceMigrationApplyRejectsForgedCompletePlans(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	s := applyProfile(t, f)
	req := applyRequest(t, ctx, s, []reference.ModuleID{"identity/postgres", "identity/risk/postgres"})
	for _, mutate := range []func(*reference.MigrationPlan){
		func(p *reference.MigrationPlan) { p.Steps = p.Steps[:len(p.Steps)-1] },
		func(p *reference.MigrationPlan) { p.Steps[0], p.Steps[1] = p.Steps[1], p.Steps[0] },
		func(p *reference.MigrationPlan) { p.Modules[0].Version++ },
		func(p *reference.MigrationPlan) { p.CatalogDigest[0]++ },
		func(p *reference.MigrationPlan) { p.BaseLedgerDigest[0]++ },
	} {
		changed := req
		changed.Plan.Modules = slices.Clone(req.Plan.Modules)
		changed.Plan.Steps = slices.Clone(req.Plan.Steps)
		mutate(&changed.Plan)
		changed.Plan = rehashApplyPlan(changed.Plan)
		result, err := s.ReferenceMigrationApply(ctx, changed)
		var conflict identity.ConflictError
		if !errors.As(err, &conflict) || result.Result.State() != reference.MigrationApplyIncompatible {
			t.Fatal("self-consistent forged plan accepted", err)
		}
		var absent bool
		if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass('public.migrations') IS NULL AND to_regclass('public.golib_migration_commands') IS NULL AND to_regnamespace('identity') IS NULL").Scan(&absent); err != nil || !absent {
			t.Fatal("forged plan caused writes", err)
		}
	}
}

func TestReferenceMigrationApplyResumesCommittedPrefix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	s := applyProfile(t, f)
	req := applyRequest(t, ctx, s, []reference.ModuleID{"identity/postgres", "identity/risk/postgres"})
	// Fail the later native schema transaction after kernel steps have committed.
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.fail_later_schema() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF to_regnamespace('identity') IS NOT NULL THEN RAISE EXCEPTION 'fixture rejection'; END IF; END $$; CREATE EVENT TRIGGER fixture_schema_failure ON ddl_command_start WHEN TAG IN ('CREATE SCHEMA') EXECUTE FUNCTION public.fail_later_schema()`); err != nil {
		t.Fatal(err)
	}
	partial, err := s.ReferenceMigrationApply(ctx, req)
	if err == nil || partial.Result.State() != reference.MigrationApplyPending || len(partial.Result.Receipts()) == 0 {
		t.Fatal("no durable prefix before controlled failure", err)
	}
	var committed int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM public.migrations").Scan(&committed); err != nil || committed == 0 || committed >= len(req.Plan.Steps) {
		t.Fatal("wrong partial native history", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "DROP EVENT TRIGGER fixture_schema_failure; DROP FUNCTION public.fail_later_schema()"); err != nil {
		t.Fatal(err)
	}
	reconstructed := applyProfile(t, f)
	completed, err := reconstructed.ReferenceMigrationApply(ctx, req)
	if err != nil || completed.Result.State() != reference.MigrationApplied || len(completed.Result.Receipts()) != 2 {
		t.Fatal("reconstructed prefix did not resume", err)
	}
	var count int
	if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM public.migrations").Scan(&count); err != nil || count != len(req.Plan.Steps) {
		t.Fatal("prefix replay or missing suffix", err)
	}
}

func TestReferenceMigrationApplyExternalPrefixDirtyAndLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	s := applyProfile(t, f)
	req := applyRequest(t, ctx, s, []reference.ModuleID{"identity/postgres", "identity/risk/postgres"})
	db := stdlib.OpenDBFromPool(f.pool.Raw())
	defer db.Close()
	b, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := b.AcquireCommand(ctx)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := s.ReferenceMigrationApply(ctx, req)
	if err == nil || locked.Result.State() != reference.MigrationApplyLocked {
		t.Fatal("lock contention not distinguished", err)
	}
	if err := owned.Release(ctx); err != nil {
		t.Fatal(err)
	}
	history, err := s.MigrationSource().Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(migrationCheckPrefix(history[:1]), b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	stale, err := s.ReferenceMigrationApply(ctx, req)
	if err == nil || stale.Result.State() != reference.MigrationApplyIncompatible {
		t.Fatal("external matching prefix adopted", err)
	}
	var absent bool
	if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass('public.golib_migration_commands') IS NULL").Scan(&absent); err != nil || !absent {
		t.Fatal("stale base wrote command state", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE public.migrations SET dirty=true,finished_at=NULL"); err != nil {
		t.Fatal(err)
	}
	dirty, err := s.ReferenceMigrationApply(ctx, req)
	if err == nil || dirty.Result.State() != reference.MigrationApplyDirty {
		t.Fatal("dirty history not distinguished", err)
	}
}

func TestReferenceMigrationApplySelectedNamespacesAndNoop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	// These roles are created only in this explicitly disposable cluster.
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if _, err := f.pool.Raw().Exec(cleanup, "DROP OWNED BY audit_writer,audit_reader,audit_retention; DROP ROLE audit_writer,audit_reader,audit_retention"); err != nil {
			t.Error("owned audit role cleanup failed", err)
		}
	})
	c, deps, _ := otpGraphConfiguration(t, f.config)
	c.Migrations = &reference.MigrationApplyPolicy{TenantID: "deployment", ActorID: "operator", LookupKey: [32]byte{8}, LockTimeout: time.Second, CleanupTimeout: time.Second}
	c.Velocity.PrimaryTimeout = 20 * time.Second
	// One physical pool connection proves discovery cannot reacquire it while
	// the native ownership session is retained across all namespaces.
	one, err := database.New(ctx, database.Config{DSN: f.pool.Raw().Config().ConnString(), MaxConns: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := one.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	deps.PostgreSQL = one
	s, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := s.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	ids := []reference.ModuleID{"identity/postgres", "identity/risk/postgres", "identity/otp/postgres", "identity/session/postgres", "identity/delivery/postgres", "authorization/postgres", "audit/postgres", "outbox/postgres", "outbox/postgres/identity"}
	req := applyRequest(t, ctx, s, ids)
	// A conflict in the last participating namespace must prevent every earlier
	// schema, ledger, preflight and command write.
	if _, err := f.pool.Raw().Exec(ctx, "CREATE TABLE public.identity_outbox_bindings(fixture int)"); err != nil {
		t.Fatal(err)
	}
	late, err := s.ReferenceMigrationApply(ctx, req)
	if err == nil || late.Result.State() != reference.MigrationApplyIncompatible {
		t.Fatal("late namespace conflict not rejected", err)
	}
	var untouched bool
	if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass('public.migrations') IS NULL AND to_regclass('public.golib_migration_commands') IS NULL AND to_regnamespace('identity') IS NULL AND to_regnamespace('audit') IS NULL").Scan(&untouched); err != nil || !untouched {
		t.Fatal("late discovery conflict caused earlier writes", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "DROP TABLE public.identity_outbox_bindings"); err != nil {
		t.Fatal(err)
	}
	// Force a transactional failure in the last physical history, after shared,
	// audit and root-outbox batches have durable command attribution.
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.fail_lifecycle() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN IF EXISTS(SELECT 1 FROM pg_event_trigger_ddl_commands() WHERE object_identity='public.identity_outbox_bindings') THEN RAISE EXCEPTION 'fixture lifecycle rejection'; END IF; END $$; CREATE EVENT TRIGGER fixture_lifecycle_failure ON ddl_command_end WHEN TAG IN ('CREATE TABLE') EXECUTE FUNCTION public.fail_lifecycle()`); err != nil {
		t.Fatal(err)
	}
	partial, err := s.ReferenceMigrationApply(ctx, req)
	if err == nil || partial.Result.State() != reference.MigrationApplyPending || len(partial.Result.Receipts()) != len(ids)-1 {
		t.Fatal("missing cross-namespace durable prefix", err, len(partial.Result.Receipts()))
	}
	if _, err := f.pool.Raw().Exec(ctx, "DROP EVENT TRIGGER fixture_lifecycle_failure; DROP FUNCTION public.fail_lifecycle()"); err != nil {
		t.Fatal(err)
	}
	reconstructed, err := reference.ComposeStores(c, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := reconstructed.Close(cleanup); err != nil {
			t.Error(err)
		}
	}()
	result, err := reconstructed.ReferenceMigrationApply(ctx, req)
	if err != nil || result.Result.State() != reference.MigrationApplied || len(result.Result.Receipts()) != len(ids) {
		t.Fatal("selected independent histories failed", err)
	}
	for _, ledger := range []string{"public.migrations", "public.golib_migrations_audit", "public.golib_migrations_outbox", "public.golib_migrations_identity_outbox"} {
		var count int
		if err := f.pool.Raw().QueryRow(ctx, "SELECT count(*) FROM "+ledger).Scan(&count); err != nil || count < 1 {
			t.Fatal("missing original namespace history", ledger, err)
		}
	}
	noop := applyRequest(t, ctx, s, ids)
	if len(noop.Plan.Steps) != 0 {
		t.Fatal("completed sources not a noop")
	}
	noop.CommandID = "migration_command_noop"
	noop.IdempotencyKey, err = identity.NewIdempotencyKey([]byte("noop-key"))
	if err != nil {
		t.Fatal(err)
	}
	result, err = s.ReferenceMigrationApply(ctx, noop)
	if err != nil || result.Result.State() != reference.MigrationApplied || len(result.Result.Receipts()) != 0 {
		t.Fatal("valid noop failed", err)
	}
}

func TestReferenceMigrationApplyCloseCancelsAndDrains(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	s := applyProfile(t, f)
	req := applyRequest(t, ctx, s, []reference.ModuleID{"identity/postgres", "identity/risk/postgres"})
	if _, err := f.pool.Raw().Exec(ctx, `CREATE FUNCTION public.pause_schema() RETURNS event_trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(827431); PERFORM pg_sleep(10); END $$; CREATE EVENT TRIGGER fixture_schema_pause ON ddl_command_start WHEN TAG IN ('CREATE SCHEMA') EXECUTE FUNCTION public.pause_schema()`); err != nil {
		t.Fatal(err)
	}
	type response struct {
		result reference.ReferenceMigrationApplyResult
		err    error
	}
	done := make(chan response, 1)
	go func() { result, err := s.ReferenceMigrationApply(ctx, req); done <- response{result, err} }()
	defer func() {
		select {
		case <-done:
		default:
		}
	}()
	// Observe a real transaction boundary, not a scheduling sleep, before Close.
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		var reached bool
		if err := f.pool.Raw().QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks WHERE locktype='advisory' AND objid=827431 AND granted)").Scan(&reached); err != nil {
			t.Fatal(err)
		}
		if reached {
			break
		}
		select {
		case early := <-done:
			t.Fatal("apply ended before cancellation boundary", early.err)
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	closeCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := s.Close(closeCtx); err != nil {
		t.Fatal("close did not drain active apply", err)
	}
	select {
	case response := <-done:
		if response.err == nil || response.result.Result.State() == reference.MigrationApplied {
			t.Fatal("cancelled migration reported applied")
		}
	case <-closeCtx.Done():
		t.Fatal("apply outlived drained close")
	}
	if _, err := s.ReferenceMigrationApply(ctx, req); err == nil {
		t.Fatal("closed owner readmitted")
	}
	if err := f.pool.Raw().Ping(ctx); err != nil {
		t.Fatal("borrowed pool closed", err)
	}
	var absent bool
	if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regnamespace('identity') IS NULL AND NOT EXISTS(SELECT 1 FROM public.golib_migration_commands WHERE completed>0)").Scan(&absent); err != nil || !absent {
		t.Fatal("cancelled SQL/ledger/receipt committed partially", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "DROP EVENT TRIGGER fixture_schema_pause; DROP FUNCTION public.pause_schema()"); err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDBFromPool(f.pool.Raw())
	defer db.Close()
	b, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := b.AcquireCommand(ctx)
	if err != nil {
		t.Fatal("cancelled owner leaked lock", err)
	}
	if err := owned.Release(ctx); err != nil {
		t.Fatal(err)
	}
}
