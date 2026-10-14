//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"sync"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	migrations "github.com/faustbrian/go-migrations/v3"
	migrationdb "github.com/faustbrian/go-migrations/v3/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

// Preparation uses the original command journal, never a parallel workflow.
func TestJournalPreparationIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal("test cluster unavailable")
	}
	defer admin.Close(ctx)
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "preparation_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(cleanup, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup failed")
		}
	}()
	config.Database = name
	db := stdlib.OpenDB(*config)
	defer db.Close()
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 12, Configure: func(native *database.PoolConfig) error { native.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(cleanup) != nil {
			t.Error("pool cleanup failed")
		}
	}()
	// Install after populated ordinary history; neither its lease nor claim may change.
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	newRequest := func() claimRequest {
		command, err := identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		return claimRequest{commandID: command, tenant: "tenant", purpose: "identity.otp.send", canonical: []byte{0xa0}, safeFields: []byte{0xa0}}
	}
	ordinary := newRequest()
	tx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	d, err := lockCommandClaim(ctx, tx, ordinary, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reserveJournal(ctx, tx, ordinary, d, [16]byte{9}, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	history, err := (PreparationMigrationSource{Base: MigrationSource{}, Version: 10}).Load(ctx)
	if err != nil || len(history) != 10 {
		t.Fatal("missing preparation history", err)
	}
	runner, err = migrations.NewRunner(PreparationMigrationSource{Base: MigrationSource{}, Version: 10}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Up(ctx); err != nil {
		t.Fatal("migration replay", err)
	}

	reserve := func(q claimRequest, owner [16]byte) (preparationReservation, error) {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			return preparationReservation{}, err
		}
		defer tx.Rollback(ctx)
		d, err := lockCommandClaim(ctx, tx, q, keys)
		if err != nil {
			return preparationReservation{}, err
		}
		if d == claimConflict {
			return preparationReservation{}, identity.ConflictError{}
		}
		r, err := reservePreparationJournal(ctx, tx, q, d, owner, time.Minute)
		if err != nil {
			return preparationReservation{}, err
		}
		return r, tx.Commit(ctx)
	}
	expire := func(q claimRequest) {
		t.Helper()
		raw, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET created_at=clock_timestamp()-interval '3 seconds',heartbeat_at=clock_timestamp()-interval '2 seconds',updated_at=clock_timestamp()-interval '2 seconds',lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, raw); err != nil {
			t.Fatal(err)
		}
	}
	start := func(q claimRequest, r preparationReservation, owner [16]byte) error {
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if err := startJournalPreparation(ctx, tx, q, r.journal, owner); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	t.Run("legacy leases after upgrade", func(t *testing.T) { testJournalLeases(t, ctx, pool) })
	t.Run("legacy terminal after upgrade", func(t *testing.T) { testJournalTerminal(t, ctx, pool) })
	t.Run("ordinary history is not adopted", func(t *testing.T) {
		if _, err := reserve(ordinary, [16]byte{1}); err == nil {
			t.Fatal("adopted legacy journal as new generation authority")
		}
	})
	t.Run("crash before generation permits fenced takeover", func(t *testing.T) {
		q := newRequest()
		first, err := reserve(q, [16]byte{1})
		if err != nil || !first.generate || first.journal.generation != 1 {
			t.Fatal("first ownership", err)
		}
		expire(q)
		second, err := reserve(q, [16]byte{2})
		if err != nil || !second.generate || second.journal.generation != 2 {
			t.Fatal("pre-generation takeover", err)
		}
		if err := start(q, first, [16]byte{1}); err == nil {
			t.Fatal("stale generation started randomness")
		}
		if err := start(q, second, [16]byte{2}); err != nil {
			t.Fatal("current owner cannot start", err)
		}
		if err := start(q, second, [16]byte{2}); err == nil {
			t.Fatal("second generation start was allowed")
		}
	})
	t.Run("crash after generation marker never regenerates", func(t *testing.T) {
		q := newRequest()
		first, err := reserve(q, [16]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		if err := start(q, first, [16]byte{1}); err != nil {
			t.Fatal(err)
		}
		expire(q)
		for range 3 {
			retry, err := reserve(q, [16]byte{2})
			if err != nil || retry.generate || retry.journal.disposition != journalBusy || retry.journal.generation != 1 || len(retry.output) != 0 {
				t.Fatal("missing ciphertext incorrectly authorized regeneration", err)
			}
		}
	})
	t.Run("matching callers have one preparation owner", func(t *testing.T) {
		q := newRequest()
		gate := make(chan struct{})
		var wg sync.WaitGroup
		results := make(chan preparationReservation, 10)
		failures := make(chan error, 10)
		for i := range 10 {
			wg.Go(func() {
				<-gate
				r, err := reserve(q, [16]byte{byte(i + 1)})
				if err != nil {
					failures <- err
					return
				}
				results <- r
			})
		}
		close(gate)
		wg.Wait()
		close(results)
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
		owners := 0
		for r := range results {
			if r.generate {
				owners++
			} else if r.journal.disposition != journalBusy {
				t.Fatal("unexpected replay disposition")
			}
		}
		if owners != 1 {
			t.Fatal("competing generators", owners)
		}
		changed := q
		changed.canonical = []byte{0xa1, 0x61, 'x', 1}
		if _, err := reserve(changed, [16]byte{11}); err == nil {
			t.Fatal("changed intent admitted")
		}
	})
	t.Run("rolled back start grants no generation history", func(t *testing.T) {
		q := newRequest()
		first, err := reserve(q, [16]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := startJournalPreparation(ctx, tx, q, first.journal, [16]byte{1}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		expire(q)
		retry, err := reserve(q, [16]byte{2})
		if err != nil || !retry.generate || retry.journal.generation != 2 {
			t.Fatal("rolled-back start survived", err)
		}
	})
	t.Run("rolled back output is still an unknown generation", func(t *testing.T) {
		q := newRequest()
		first, err := reserve(q, [16]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		if err := start(q, first, [16]byte{1}); err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		if err := retainJournalPreparation(ctx, tx, q, first.journal, [16]byte{1}, []byte{0xc7}); err != nil {
			t.Fatal(err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		expire(q)
		retry, err := reserve(q, [16]byte{2})
		if err != nil || retry.generate || retry.journal.disposition != journalBusy || len(retry.output) != 0 {
			t.Fatal("rolled-back output authorized regeneration", err)
		}
	})
	t.Run("lease expiry during lock wait denies generation", func(t *testing.T) {
		q := newRequest()
		first, err := reserve(q, [16]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		raw, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
		var until time.Time
		if err := tx.QueryRow(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()+interval '1 second' WHERE command_id=$1 RETURNING lease_until`, raw).Scan(&until); err != nil {
			t.Fatal(err)
		}
		waiting, stopWait := context.WithTimeout(ctx, 5*time.Second)
		started := make(chan uint32, 1)
		finished := make(chan error, 1)
		consumed := false
		defer func() {
			stopWait()
			if !consumed {
				<-finished
			}
		}()
		go func() {
			work, err := pool.Raw().Begin(waiting)
			if err != nil {
				started <- 0
				finished <- err
				return
			}
			defer work.Rollback(ctx)
			var pid uint32
			if err := work.QueryRow(waiting, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				started <- 0
				finished <- err
				return
			}
			started <- pid
			err = startJournalPreparation(waiting, work, q, first.journal, [16]byte{1})
			if err == nil {
				err = work.Commit(waiting)
			}
			finished <- err
		}()
		pid := <-started
		if pid == 0 {
			t.Fatal("start transaction unavailable")
		}
		blocked := false
		for range 1000 {
			if err := pool.Raw().QueryRow(waiting, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')`, pid).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
		}
		if !blocked {
			t.Fatal("generation start did not reach the held journal lock")
		}
		// Let the unchanged primary deadline cross while the actual start query
		// is waiting. A time read before that wait must now be insufficient.
		if _, err := tx.Exec(ctx, `SELECT pg_sleep_until($1::timestamptz+interval '10 milliseconds')`, until); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		err = <-finished
		consumed = true
		if err == nil {
			t.Fatal("pre-wait lease evidence authorized generation")
		}
		retry, err := reserve(q, [16]byte{2})
		if err != nil || !retry.generate || retry.journal.generation != 2 {
			t.Fatal("failed stale start changed history", err)
		}
	})
	t.Run("retained output survives takeover without replacement", func(t *testing.T) {
		q := newRequest()
		first, err := reserve(q, [16]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		if err := start(q, first, [16]byte{1}); err != nil {
			t.Fatal(err)
		}
		// This owner layer stores an authenticated-envelope wire image, not plaintext.
		// Authentication/opening remains the native feature codec's responsibility.
		output := bytes.Repeat([]byte{0xc7}, 128)
		persist := func(r preparationReservation, owner [16]byte, wire []byte) error {
			tx, err := pool.Raw().Begin(ctx)
			if err != nil {
				return err
			}
			defer tx.Rollback(ctx)
			if err := retainJournalPreparation(ctx, tx, q, r.journal, owner, wire); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
		if err := persist(first, [16]byte{1}, output); err != nil {
			t.Fatal(err)
		}
		if err := persist(first, [16]byte{1}, output); err != nil {
			t.Fatal("same output was not idempotent", err)
		}
		if err := persist(first, [16]byte{1}, bytes.Repeat([]byte{0xc8}, 128)); err == nil {
			t.Fatal("original output replaced")
		}
		expire(q)
		restarted, err := reserve(q, [16]byte{2})
		if err != nil || restarted.generate || restarted.journal.generation != 2 || restarted.outputGeneration != 1 || !bytes.Equal(restarted.output, output) {
			t.Fatal("restart lost original output provenance", err)
		}
		if err := start(q, restarted, [16]byte{2}); err == nil {
			t.Fatal("takeover regenerated original output")
		}
		if err := persist(first, [16]byte{1}, output); err == nil {
			t.Fatal("stale owner persisted")
		}
		if err := persist(restarted, [16]byte{2}, output); err == nil {
			t.Fatal("takeover claimed original generation")
		}
		raw, _ := base64.RawURLEncoding.DecodeString(string(q.commandID))
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_ciphertext=$2 WHERE command_id=$1`, raw, []byte{1}); err == nil {
			t.Fatal("SQL replaced immutable output")
		}
		if _, err := pool.Raw().Exec(ctx, `UPDATE identity.commands SET preparation_started_generation=NULL,preparation_ciphertext=NULL,preparation_ciphertext_generation=NULL WHERE command_id=$1`, raw); err == nil {
			t.Fatal("SQL erased original generation")
		}
		// No preparation phase itself issued a credential or terminal receipt.
		var state string
		var plan, receipt []byte
		if err := pool.Raw().QueryRow(ctx, `SELECT state,command_plan,result FROM identity.commands WHERE command_id=$1`, raw).Scan(&state, &plan, &receipt); err != nil || state != "pending" || plan != nil || receipt != nil {
			t.Fatal("preparation fabricated execution", err)
		}
	})
}
