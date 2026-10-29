//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	apikeypg "github.com/faustbrian/go-identity/apikey/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestMetadataPopulatedIndexDDLIsBoundedAndTransactional(t *testing.T) {
	f := setupNativeConsumer(t)
	service, err := apikeypg.NewService(f.pool, f.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.InitializeConfiguration(f.ctx, baselineTenant); err != nil {
		t.Fatal(err)
	}
	metadataIssue(t, f, service, f.caller, "populated-metadata-migration")
	before := metadataState(t, f)
	steps, err := (apikeypg.MetadataMigrationSource{Version: 1}).Load(f.ctx)
	if err != nil || len(steps) != 1 {
		t.Fatal(err)
	}
	locker, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = locker.Rollback(cleanup)
	}()
	if _, err := locker.Exec(f.ctx, `LOCK TABLE identity_api_keys.keys IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ddl, err := f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = ddl.Rollback(cleanup)
	}()
	if _, err := ddl.Exec(f.ctx, `SET LOCAL lock_timeout='100ms'; SET LOCAL statement_timeout='1s'`); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, buildErr := ddl.Exec(f.ctx, steps[0].UpSQL())
	var failure *pgconn.PgError
	if !errors.As(buildErr, &failure) || failure.Code != "55P03" || time.Since(started) > time.Second {
		_ = ddl.Rollback(f.ctx)
		t.Fatal("selected ordinary index build did not honor bounded DDL lock contention")
	}
	if err := ddl.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	if err := locker.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	assertMetadataIndexAbsent(t, f)
	ddl, err = f.pool.Raw().Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ddl.Exec(f.ctx, steps[0].UpSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := ddl.Exec(f.ctx, `SELECT 1/0`); err == nil {
		t.Fatal("fixture did not fail after transactional index creation")
	}
	if err := ddl.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	assertMetadataIndexAbsent(t, f)
	installMetadataPages(t, f, false)
	if after := metadataState(t, f); after != before {
		t.Fatal("bounded failed/retried metadata DDL rewrote key authority or attempts")
	}
	// The optional organization history is independent and can follow populated
	// self-owned metadata; existing histories and rows remain unchanged.
	installOrganizationKeyOwners(t, f)
	installMetadataPages(t, f, true)
	if after := metadataState(t, f); after[0] == "" || after[2] != before[2] {
		t.Fatal("optional organization metadata migration changed command effects")
	}
}

func assertMetadataIndexAbsent(t *testing.T, f nativeConsumerFixture) {
	t.Helper()
	var absent bool
	if err := f.pool.Raw().QueryRow(f.ctx, `SELECT to_regclass('identity_api_keys.identity_api_keys_metadata_user_page') IS NULL`).Scan(&absent); err != nil || !absent {
		t.Fatal("failed transactional metadata index build survived rollback", err)
	}
}
