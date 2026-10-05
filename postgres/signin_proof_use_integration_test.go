//go:build integration

package postgres

import (
	"context"
	"errors"
	"math"
	"os"
	"strings"
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

// This harness proves private custody storage and SQL atomicity, not private
// proof provenance, current authority, public session issuance or its recovery.
func TestSignInProofUseIntegration(t *testing.T) {
	dsn := os.Getenv("IDENTITY_POSTGRES_TEST_DSN")
	config, err := pgx.ParseConfig(dsn)
	if dsn == "" || err != nil || config.Host != "127.0.0.1" || config.Database != "identity_test" {
		t.Fatal("explicit disposable loopback identity_test required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if admin.Close(c) != nil {
			t.Error("admin cleanup")
		}
	})
	id, err := identity.NewSubjectID()
	if err != nil {
		t.Fatal(err)
	}
	name := "signin_use_" + string(id)
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if _, err := admin.Exec(c, "DROP DATABASE "+quoted); err != nil {
			t.Error("database cleanup")
		}
	})
	config.Database = name
	db := stdlib.OpenDB(*config)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error("migration database cleanup")
		}
	})
	backend, err := migrationdb.New(db)
	if err != nil {
		t.Fatal(err)
	}
	base, err := migrations.NewRunner(MigrationSource{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = base.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES('import','01ARZ3NDEKTSV4RRFFQ69G5FAV','banned',18446744073709551615)`); err != nil {
		t.Fatal(err)
	}
	runner, err := migrations.NewRunner(SignInProofUseMigrationSource{Base: MigrationSource{}, Version: 10}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = runner.Up(ctx); err != nil {
		t.Fatal("migration replay", err)
	}
	var user, status, version string
	if err = db.QueryRowContext(ctx, `SELECT user_id,status,version::text FROM identity.users WHERE tenant_id='import'`).Scan(&user, &status, &version); err != nil || user != "01ARZ3NDEKTSV4RRFFQ69G5FAV" || status != "banned" || version != "18446744073709551615" {
		t.Fatal("populated migration changed authority", err)
	}
	pool, err := database.Connect(ctx, database.Config{DSN: dsn, MaxConns: 4, Configure: func(p *database.PoolConfig) error { p.ConnConfig.Database = name; return nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if pool.Close(c) != nil {
			t.Error("pool cleanup")
		}
	})
	open := func(binding identity.CommandBinding) (Work, pgx.Tx) {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		bounded, stop := context.WithTimeout(ctx, 3*time.Second)
		w := Work{state: &workState{tx: tx, ctx: bounded, cancel: stop, binding: binding, generation: 1}}
		t.Cleanup(func() {
			invalidateWork(w)
			c, done := context.WithTimeout(context.Background(), time.Second)
			defer done()
			if err := tx.Rollback(c); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
				t.Error("transaction cleanup")
			}
		})
		return w, tx
	}
	binding := func() identity.CommandBinding {
		t.Helper()
		b := codecBinding()
		b.CommandID, err = identity.NewCommandID()
		if err != nil {
			t.Fatal(err)
		}
		b.OperationID, b.SchemaID, b.RecordID = "identity.session.issue", "session-issue", "session"
		return b
	}
	count := func(proof string) int {
		t.Helper()
		var n int
		if err := pool.Raw().QueryRow(ctx, `SELECT count(*) FROM identity.signin_proof_uses WHERE proof_id=$1`, proof).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	const proof = "aaaaaaaaaaaaaaaaaaaaaa"
	expires := time.Now().UTC().Add(time.Minute).Truncate(time.Second).Add(123456789 * time.Nanosecond)
	t.Run("outstanding cursor cannot restore failed staging", func(t *testing.T) {
		w, tx := open(binding())
		alias := w
		rows, err := w.Query(ctx, "SELECT 1")
		if err != nil {
			t.Fatal(err)
		}
		if err := w.stageSignInProofUse(ctx, "original-authority", "eeeeeeeeeeeeeeeeeeeeee", 1, expires); err == nil {
			t.Fatal("open cursor admitted staging")
		}
		rows.Close()
		if w.usable() == nil || alias.usable() == nil {
			t.Fatal("closing cursor revived failed Work")
		}
		if _, err := alias.Exec(ctx, "SELECT 1"); err == nil {
			t.Fatal("alias retained execution")
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	})
	b := binding()
	w, tx := open(b)
	if err := w.stageSignInProofUse(ctx, "original-authority", proof, math.MaxUint64, expires); err != nil {
		t.Fatal("native staging", err)
	}
	var storedVersion, storedExpiry string
	if err := tx.QueryRow(ctx, `SELECT proof_version::text,expires_at FROM identity.signin_proof_uses`).Scan(&storedVersion, &storedExpiry); err != nil || storedVersion != "18446744073709551615" || storedExpiry != expires.Format("2006-01-02T15:04:05.000000000Z") {
		t.Fatal("original proof metadata changed", err)
	}
	if err := tx.Rollback(ctx); err != nil || count(proof) != 0 {
		t.Fatal("rollback consumed proof", err)
	}
	w, tx = open(b)
	if err := w.stageSignInProofUse(ctx, "original-authority", proof, math.MaxUint64, expires); err != nil {
		t.Fatal("proven rollback did not preserve eligibility", err)
	}
	if err := tx.Commit(ctx); err != nil || count(proof) != 1 {
		t.Fatal("committed use missing", err)
	}
	for _, scope := range []string{"same", "foreign tenant", "foreign user"} {
		next := binding()
		if scope == "foreign tenant" {
			next.TenantID = "other"
		}
		if scope == "foreign user" {
			next.UserID = "other"
		}
		w, tx := open(next)
		var conflict identity.ConflictError
		if err := w.stageSignInProofUse(ctx, "original-authority", proof, 1, expires); !errors.As(err, &conflict) || w.usable() == nil {
			t.Fatal("used identity rebound across scope/version", err)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
	}
	w, tx = open(binding())
	if err := w.stageSignInProofUse(ctx, "independent-authority", proof, 1, expires); err != nil {
		t.Fatal("independent authentication namespace collided", err)
	}
	if err := tx.Commit(ctx); err != nil || count(proof) != 2 {
		t.Fatal(err)
	}
	w, tx = open(b)
	var conflict identity.ConflictError
	if err := w.stageSignInProofUse(ctx, "original-authority", strings.Repeat("b", 22), 1, expires); !errors.As(err, &conflict) || w.usable() == nil {
		t.Fatal("one command acquired another proof", err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	t.Run("concurrent single winner", func(t *testing.T) {
		const parallel = "cccccccccccccccccccccc"
		start, results := make(chan struct{}), make(chan error, 2)
		var joined sync.WaitGroup
		var works [2]Work
		var transactions [2]pgx.Tx
		// Acquire every fallible fixture before starting either goroutine.
		for i := range works {
			works[i], transactions[i] = open(binding())
		}
		for i := range works {
			work, transaction := works[i], transactions[i]
			joined.Add(1)
			go func() {
				defer joined.Done()
				<-start
				err := work.stageSignInProofUse(ctx, "original-authority", parallel, 1, expires)
				if err == nil {
					err = transaction.Commit(ctx)
				} else {
					if rollback := transaction.Rollback(ctx); rollback != nil {
						err = rollback
					}
				}
				invalidateWork(work)
				results <- err
			}()
		}
		close(start)
		joined.Wait()
		close(results)
		wins, denials := 0, 0
		for err := range results {
			var conflict identity.ConflictError
			if err == nil {
				wins++
			} else if errors.As(err, &conflict) {
				denials++
			} else {
				t.Fatal("unexpected concurrent result", err)
			}
		}
		if wins != 1 || denials != 1 || count(parallel) != 1 {
			t.Fatal("duplicate proof admitted")
		}
	})

	t.Run("expiry during uniqueness lock wait", func(t *testing.T) {
		const waiting = "dddddddddddddddddddddd"
		first, lock := open(binding())
		if err := first.stageSignInProofUse(ctx, "original-authority", waiting, 1, expires); err != nil {
			t.Fatal(err)
		}
		second, pending := open(binding())
		primaryNow, err := second.DatabaseTime(ctx)
		if err != nil {
			t.Fatal(err)
		}
		deadline := primaryNow.Add(500 * time.Millisecond)
		result := make(chan error, 1)
		staging, cancelStaging := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			result <- second.stageSignInProofUse(staging, "original-authority", waiting, 1, deadline)
		}()
		// Subtest cleanup runs before parent-owned Work/transaction cleanup,
		// including monitoring and rollback failures before result collection.
		t.Cleanup(func() { cancelStaging(); <-done })
		blocked := false
		for limit := time.Now().Add(time.Second); time.Now().Before(limit); {
			if err := pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND wait_event_type='Lock' AND query LIKE '%identity.signin_proof_uses%')`, name).Scan(&blocked); err != nil {
				t.Fatal(err)
			}
			if blocked {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if !blocked {
			_ = lock.Rollback(ctx)
			<-result
			t.Fatal("uniqueness wait not established")
		}
		for {
			var now time.Time
			if err := pool.Raw().QueryRow(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
				t.Fatal(err)
			}
			if !now.Before(deadline) {
				break
			}
			time.Sleep(5 * time.Millisecond)
		}
		if err := lock.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		var denied identity.ForbiddenError
		if err := <-result; !errors.As(err, &denied) || second.usable() == nil {
			t.Fatal("expired original proof accepted after wait", err)
		}
		if err := pending.Rollback(ctx); err != nil || count(waiting) != 0 {
			t.Fatal("expired provisional prefix survived", err)
		}
	})
}
