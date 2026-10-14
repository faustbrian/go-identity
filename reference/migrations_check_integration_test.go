//go:build integration

package reference_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/reference"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestReferenceMigrationCheckNativeReadOnlySnapshots(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := newLiveStoresProfile(t, ctx, false)
	role := pgx.Identifier{"check_" + f.pool.Raw().Config().ConnConfig.Database}.Sanitize()
	if _, err := f.pool.Raw().Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal("read-only fixture principal", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if _, err := f.pool.Raw().Exec(cleanup, "DROP OWNED BY "+role+"; DROP ROLE "+role); err != nil {
			t.Error("read-only fixture principal cleanup", err)
		}
	})
	readPool, err := database.New(ctx, database.Config{DSN: f.pool.Raw().Config().ConnString(), MaxConns: 2,
		SessionInit: func(ctx context.Context, conn *pgx.Conn) error {
			_, err := conn.Exec(ctx, "SET SESSION AUTHORIZATION "+role)
			return err
		}})
	if err != nil {
		t.Fatal("read-only fixture pool", err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := readPool.Close(cleanup); err != nil {
			t.Error(err)
		}
	})
	if _, err := readPool.Raw().Exec(ctx, "CREATE TABLE public.forbidden_check_write(id int)"); err == nil {
		t.Fatal("read-only principal can write")
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
	request := reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"identity/risk/postgres", "identity/postgres"}}
	check := func(expected reference.MigrationCompatibility, kernel, risk uint64) {
		t.Helper()
		result, err := stores.ReferenceMigrationCheck(ctx, request)
		if err != nil || len(result.Statuses) != 2 {
			t.Fatal("authoritative read-only check", err)
		}
		for i, status := range result.Statuses {
			current, required := kernel, uint64(9)
			if i == 1 {
				current, required = risk, 1011
			}
			if status.CurrentVersion != current || status.RequiredVersion != required || status.Compatibility != expected {
				t.Fatal("wrong authoritative migration status", status)
			}
		}
		result.Statuses[0].CurrentVersion = 9999
	}
	check(reference.MigrationRequired, 0, 0)
	var ledgerAbsent bool
	if err := f.pool.Raw().QueryRow(ctx, "SELECT to_regclass('public.migrations') IS NULL").Scan(&ledgerAbsent); err != nil || !ledgerAbsent {
		t.Fatal("Check prepared a ledger", err)
	}
	db := stdlib.OpenDBFromPool(f.pool.Raw())
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	owned, err := backend.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	check(reference.MigrationRequired, 0, 0)
	if err := owned.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "CREATE SCHEMA risk_store"); err != nil {
		t.Fatal(err)
	}
	check(reference.MigrationIncompatible, 0, 0)
	if _, err := f.pool.Raw().Exec(ctx, "DROP SCHEMA risk_store"); err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(f.stores.MigrationSource(), backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("native installation", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "GRANT SELECT ON public.migrations TO "+role); err != nil {
		t.Fatal(err)
	}
	check(reference.MigrationCompatible, 9, 1011)
	check(reference.MigrationCompatible, 9, 1011)
	var original string
	var finished time.Time
	if err := f.pool.Raw().QueryRow(ctx, "SELECT checksum,finished_at FROM public.migrations WHERE version=1011").Scan(&original, &finished); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE public.migrations SET checksum='sha256:'||repeat('1',64) WHERE version=1011"); err != nil {
		t.Fatal(err)
	}
	check(reference.MigrationIncompatible, 9, 1011)
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE public.migrations SET checksum=$1,dirty=true,finished_at=NULL WHERE version=1011", original); err != nil {
		t.Fatal(err)
	}
	check(reference.MigrationDirty, 9, 1011)
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE public.migrations SET dirty=false,finished_at=$1,version=2000 WHERE version=1011", finished); err != nil {
		t.Fatal(err)
	}
	check(reference.MigrationIncompatible, 9, 1010)
	if _, err := f.pool.Raw().Exec(ctx, "UPDATE public.migrations SET version=1011 WHERE version=2000"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "ALTER TABLE public.migrations RENAME TO original_migrations; CREATE VIEW public.migrations AS SELECT * FROM public.original_migrations"); err != nil {
		t.Fatal(err)
	}
	check(reference.MigrationIncompatible, 0, 0)
	if _, err := f.pool.Raw().Exec(ctx, "DROP VIEW public.migrations; ALTER TABLE public.original_migrations RENAME TO migrations"); err != nil {
		t.Fatal(err)
	}
	check(reference.MigrationCompatible, 9, 1011)
	expired, stopExpired := context.WithDeadline(ctx, time.Now().Add(-time.Second))
	defer stopExpired()
	if result, err := stores.ReferenceMigrationCheck(expired, request); !errors.Is(err, context.DeadlineExceeded) || len(result.Statuses) != 0 {
		t.Fatal("expired check returned compatibility", err)
	}
	if _, err := f.pool.Raw().Exec(ctx, "REVOKE SELECT ON public.migrations FROM "+role); err != nil {
		t.Fatal(err)
	}
	if result, err := stores.ReferenceMigrationCheck(ctx, request); err == nil || len(result.Statuses) != 0 {
		t.Fatal("inaccessible ledger fabricated compatibility")
	}
	if _, err := f.pool.Raw().Exec(ctx, "GRANT SELECT ON public.migrations TO "+role); err != nil {
		t.Fatal(err)
	}
	for _, ids := range [][]reference.ModuleID{nil, {"identity/postgres", "identity/postgres"}, {"identity/otp/postgres"}, {"pkg/identity/postgres"}, {"unknown"}} {
		result, err := stores.ReferenceMigrationCheck(ctx, reference.ReferenceMigrationCheckRequest{Modules: ids})
		var invalid identity.InvalidInputError
		if !errors.As(err, &invalid) || len(result.Statuses) != 0 {
			t.Fatal("invalid selection accepted", err)
		}
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if result, err := stores.ReferenceMigrationCheck(canceled, request); !errors.Is(err, context.Canceled) || len(result.Statuses) != 0 {
		t.Fatal("cancellation lost", err)
	}
	if err := stores.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if result, err := stores.ReferenceMigrationCheck(ctx, request); err == nil || len(result.Statuses) != 0 {
		t.Fatal("closed owner checked history")
	}
	if err := readPool.Raw().Ping(ctx); err != nil {
		t.Fatal("Check closed borrowed pool", err)
	}
}

// A namespace's base ledger entry cannot authorize later unrecorded objects.
func TestReferenceMigrationCheckRejectsUnmanagedDeliverySuffix(t *testing.T) {
	for _, installed := range []migrations.Version{1011, 1100, 1250} {
		t.Run(strconv.FormatUint(uint64(installed), 10), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			f := newLiveStores(t, ctx)
			config, deps, _ := otpGraphConfiguration(t, f.config)
			deps.PostgreSQL = f.pool
			stores, err := reference.ComposeStores(config, deps)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = stores.Close(context.Background()) })
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
				if step.Version() <= installed {
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
			request := reference.ReferenceMigrationCheckRequest{Modules: []reference.ModuleID{"identity/delivery/postgres"}}
			assert := func(want reference.MigrationCompatibility) {
				t.Helper()
				result, err := stores.ReferenceMigrationCheck(ctx, request)
				if err != nil || len(result.Statuses) != 1 || result.Statuses[0].Compatibility != want {
					t.Fatalf("delivery suffix compatibility: got %+v, error %v, want %v", result, err, want)
				}
			}
			assert(reference.MigrationRequired)
			if _, err := f.pool.Raw().Exec(ctx, "CREATE TABLE identity.delivery_policy_profiles(unmanaged boolean)"); err != nil {
				t.Fatal(err)
			}
			assert(reference.MigrationIncompatible)
			if _, err := f.pool.Raw().Exec(ctx, "DROP TABLE identity.delivery_policy_profiles"); err != nil {
				t.Fatal(err)
			}
			assert(reference.MigrationRequired)
			if installed == 1011 {
				if _, err := f.pool.Raw().Exec(ctx, "ALTER TABLE identity.commands ADD COLUMN preparation_profile smallint"); err != nil {
					t.Fatal(err)
				}
				assert(reference.MigrationIncompatible)
				if _, err := f.pool.Raw().Exec(ctx, "ALTER TABLE identity.commands DROP COLUMN preparation_profile"); err != nil {
					t.Fatal(err)
				}
				assert(reference.MigrationRequired)
			}
			if installed == 1100 {
				if _, err := f.pool.Raw().Exec(ctx, "CREATE TABLE otp_store.lockout_key_binding(unmanaged boolean)"); err != nil {
					t.Fatal(err)
				}
				assert(reference.MigrationIncompatible)
				if _, err := f.pool.Raw().Exec(ctx, "DROP TABLE otp_store.lockout_key_binding"); err != nil {
					t.Fatal(err)
				}
				assert(reference.MigrationRequired)
			}
			if _, err := f.pool.Raw().Exec(ctx, "CREATE TABLE identity.delivery_receipts(unmanaged boolean)"); err != nil {
				t.Fatal(err)
			}
			assert(reference.MigrationRequired) // Unselected receipt owner contributes no guard.
			config.Delivery.Enqueue.ReceiptTracking = true
			selected, err := reference.ComposeStores(config, deps)
			if err != nil {
				t.Fatal(err)
			}
			result, err := selected.ReferenceMigrationCheck(ctx, request)
			if err != nil || len(result.Statuses) != 1 || result.Statuses[0].Compatibility != reference.MigrationIncompatible {
				t.Fatal("selected receipt object accepted without history", result, err)
			}
			if err := selected.Close(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := f.pool.Raw().Exec(ctx, "DROP TABLE identity.delivery_receipts"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type migrationCheckPrefix []migrations.Migration

func (p migrationCheckPrefix) Load(ctx context.Context) ([]migrations.Migration, error) {
	return append([]migrations.Migration(nil), p...), ctx.Err()
}
