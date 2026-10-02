//go:build integration

package postgres

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

type workScannerEscape struct{ called bool }

func (s *workScannerEscape) ScanRow(pgx.Rows) error { s.called = true; return nil }

type workRewriterEscape struct{ called bool }

func (s *workRewriterEscape) RewriteQuery(context.Context, *pgx.Conn, string, []any) (string, []any, error) {
	s.called = true
	return "COMMIT", nil, nil
}

func testWorkExecution(t *testing.T, ctx context.Context, pool *database.Pool) {
	binding := codecBinding()
	binding.CommandID = "AAAAAAAAAAAAAAAAAAAASA"
	c, err := identity.NewUserCreationCommand(identity.CreateUserCommand{Binding: binding, Status: identity.StatusActive})
	if err != nil {
		t.Fatal("work command")
	}
	q, err := prepareClaim(c, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	keys := claimKeys{current: 1, retained: map[uint32][32]byte{1: {1}}}
	owner := [16]byte{9}
	reservationTx, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reservationTx.Rollback(ctx)
	d, err := lockCommandClaim(ctx, reservationTx, q, keys)
	if err != nil {
		t.Fatal(err)
	}
	r, err := reserveJournal(ctx, reservationTx, q, d, owner, time.Minute)
	if err != nil || reservationTx.Commit(ctx) != nil {
		t.Fatal("work reservation")
	}
	open := func(t *testing.T) (Work, pgx.Tx) {
		t.Helper()
		tx, err := pool.Raw().Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { tx.Rollback(ctx) })
		fence, err := beginJournal(ctx, tx, q, keys, r, owner)
		if err != nil {
			t.Fatal(err)
		}
		w, err := newWork(ctx, tx, binding, q, fence)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { invalidateWork(w) })
		return w, tx
	}
	t.Run("execute and rollback", func(t *testing.T) {
		w, tx := open(t)
		if got, err := w.Scope(); err != nil || got != binding {
			t.Fatal("scope changed")
		}
		if now, err := w.DatabaseTime(ctx); err != nil || !postgresExactTime(now) || now.Location() != time.UTC {
			t.Fatal("database time invalid")
		}
		n, err := w.Exec(ctx, `INSERT INTO identity.users(tenant_id,user_id,status,version) VALUES($1,$2,'active',$3::numeric)`, "tenant-a", "work-owned", "18446744073709551615")
		if err != nil || n != 1 {
			t.Fatalf("work mutation failed: %v", err)
		}
		rows, err := w.Query(ctx, `SELECT version::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2`, "tenant-a", "work-owned")
		if err != nil || !rows.Next() {
			t.Fatal("work result")
		}
		var version string
		if rows.Scan(&version) != nil || version != "18446744073709551615" || rows.Next() || rows.Err() != nil {
			t.Fatal("work scan changed value")
		}
		alias := w
		invalidateWork(w)
		if _, err := alias.Exec(ctx, "SELECT 1"); err == nil {
			t.Fatal("closed alias executed")
		}
		if tx.Rollback(ctx) != nil {
			t.Fatal("domain rollback")
		}
		var exists bool
		if pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.users WHERE user_id='work-owned')`).Scan(&exists) != nil || exists {
			t.Fatal("work committed independently")
		}
	})
	for _, sql := range []string{"COMMIT", "ROLLBACK", "BEGIN", "SAVEPOINT child", "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE", "SELECT 1; COMMIT"} {
		t.Run(sql, func(t *testing.T) {
			w, tx := open(t)
			if _, err := w.Exec(ctx, sql); err == nil {
				t.Fatal("transaction ownership escaped")
			}
			if tx.Conn().PgConn().TxStatus() == 'I' {
				t.Fatal("transaction closed through Work")
			}
		})
	}
	t.Run("driver option denied", func(t *testing.T) {
		w, _ := open(t)
		escape := &workRewriterEscape{}
		if _, err := w.Exec(ctx, "SELECT 1", escape); err == nil || escape.called {
			t.Fatal("driver callback escaped")
		}
	})
	t.Run("prepared alias cannot close transaction", func(t *testing.T) {
		w, tx := open(t)
		if _, err := tx.Conn().Prepare(ctx, "SELECT 17", "COMMIT"); err != nil {
			t.Fatal("prepared alias fixture")
		}
		t.Cleanup(func() { tx.Conn().Deallocate(ctx, "SELECT 17") })
		rows, err := w.Query(ctx, "SELECT 17")
		if err != nil || !rows.Next() {
			t.Fatal("SQL was replaced by prepared name")
		}
		var value int32
		if rows.Scan(&value) != nil || value != 17 {
			t.Fatal("prepared alias replaced SQL")
		}
		rows.Close()
		if tx.Conn().PgConn().TxStatus() != 'T' {
			t.Fatal("prepared alias escaped transaction ownership")
		}
	})
	t.Run("driver errors redacted", func(t *testing.T) {
		w, _ := open(t)
		_, err := w.Query(ctx, "SELECT 'synthetic-private-value'::integer")
		var unavailable identity.UnavailableError
		if !errors.As(err, &unavailable) {
			t.Fatalf("driver error misclassified: %v", err)
		}
		if err.Error() != "identity: unavailable" {
			t.Fatal("driver diagnostics leaked")
		}
	})
	t.Run("row scanner denied", func(t *testing.T) {
		w, _ := open(t)
		rows, err := w.Query(ctx, "SELECT 1")
		if err != nil || !rows.Next() {
			t.Fatal("scanner fixture")
		}
		escape := &workScannerEscape{}
		if rows.Scan(escape) == nil || escape.called {
			t.Fatal("raw rows escaped")
		}
		if _, err := w.Exec(ctx, "SELECT 1"); err == nil {
			t.Fatal("failed Work resumed")
		}
	})
	t.Run("active rows and closure", func(t *testing.T) {
		w, _ := open(t)
		rows, err := w.Query(ctx, "SELECT 1")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Query(ctx, "SELECT 2"); err == nil {
			t.Fatal("overlapping query admitted")
		}
		invalidateWork(w)
		if rows.Next() || rows.Scan(new(int32)) == nil {
			t.Fatal("rows survived Work closure")
		}
	})
	t.Run("row budget", func(t *testing.T) {
		w, _ := open(t)
		rows, err := w.Query(ctx, "SELECT generate_series(1,257)")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for rows.Next() {
			n++
		}
		if n != 256 || rows.Err() == nil {
			t.Fatal("unbounded row result")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		w, _ := open(t)
		stopped, cancel := context.WithCancel(ctx)
		cancel()
		_, err := w.Exec(stopped, "SELECT 1")
		var cancelled identity.CancelledError
		if !errors.As(err, &cancelled) {
			t.Fatalf("cancelled Work admitted: %v", err)
		}
	})
	t.Run("caller deadline cancels active query", func(t *testing.T) {
		w, _ := open(t)
		call, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
		defer cancel()
		_, err := w.Exec(call, "SELECT pg_sleep(1)")
		var deadline identity.DeadlineExceededError
		if !errors.As(err, &deadline) {
			t.Fatalf("query deadline classification lost: %v", err)
		}
		if _, err := w.Exec(ctx, "SELECT 1"); err == nil {
			t.Fatal("failed owner executed")
		}
	})
	t.Run("caller cancellation denies prefetched row", func(t *testing.T) {
		w, _ := open(t)
		call, cancel := context.WithCancel(ctx)
		defer cancel()
		rows, err := w.Query(call, "SELECT 1")
		if err != nil {
			t.Fatal("prefetched cancellation fixture")
		}
		defer rows.Close()
		cancel()
		if rows.Next() {
			t.Fatal("prefetched row survived caller cancellation")
		}
		var cancelled identity.CancelledError
		if !errors.As(rows.Err(), &cancelled) {
			t.Fatal("cursor cancellation classification lost")
		}
		if _, err := w.Exec(ctx, "SELECT 2"); !errors.As(err, &cancelled) {
			t.Fatal("cancelled cursor did not poison Work")
		}
	})
	t.Run("caller cancellation denies buffered scan", func(t *testing.T) {
		w, _ := open(t)
		call, cancel := context.WithCancel(ctx)
		defer cancel()
		rows, err := w.Query(call, "SELECT 1")
		if err != nil || !rows.Next() {
			t.Fatal("buffered scan cancellation fixture")
		}
		defer rows.Close()
		cancel()
		value := int32(17)
		var cancelled identity.CancelledError
		if err := rows.Scan(&value); !errors.As(err, &cancelled) || value != 17 {
			t.Fatal("buffered scan survived cancellation or mutated destination")
		}
		if !errors.As(rows.Err(), &cancelled) {
			t.Fatal("scan cancellation classification lost")
		}
		if _, err := w.Exec(ctx, "SELECT 2"); !errors.As(err, &cancelled) {
			t.Fatal("cancelled scan did not poison Work")
		}
	})
	t.Run("construction cannot restart lease", func(t *testing.T) {
		_, tx := open(t)
		fence, err := beginJournal(ctx, tx, q, keys, r, owner)
		if err != nil {
			t.Fatal(err)
		}
		fence.readStarted = fence.readStarted.Add(-2 * time.Minute)
		if _, err := newWork(ctx, tx, binding, q, fence); err == nil {
			t.Fatal("construction renewed expired evidence")
		}
	})
	t.Run("byte budget", func(t *testing.T) {
		w, _ := open(t)
		rows, err := w.Query(ctx, "SELECT repeat('x',1048577)")
		if err != nil {
			t.Fatal(err)
		}
		if rows.Next() || rows.Err() == nil {
			t.Fatal("oversized result delivered")
		}
	})
	t.Run("empty bytes remain nonnull", func(t *testing.T) {
		w, _ := open(t)
		rows, err := w.Query(ctx, "SELECT $1::bytea IS NULL,octet_length($1::bytea)", []byte{})
		if err != nil || !rows.Next() {
			t.Fatal("empty bytes fixture")
		}
		var null bool
		var length int32
		if rows.Scan(&null, &length) != nil || null || length != 0 {
			t.Fatal("empty bytes changed in SQL")
		}
		rows.Close()
	})
	t.Run("fixed scalar roundtrip", func(t *testing.T) {
		w, _ := open(t)
		instant := time.Date(2026, 10, 2, 1, 2, 3, 4000, time.UTC)
		rows, err := w.Query(ctx, `SELECT $1::boolean,$2::int8::text,$3::int2,$4::int4,$5::int8,$6::int8,$7::numeric::text,$8::float8,$9::text,$10::bytea,$11::timestamptz,$12::text IS NULL`, true, int(-9), int16(math.MinInt16), int32(math.MinInt32), int64(math.MaxInt64), uint32(math.MaxUint32), uint64(math.MaxUint64), float64(-1.5), "", []byte{1, 2}, instant, nil)
		if err != nil || !rows.Next() {
			t.Fatalf("fixed scalar fixture: %v", err)
		}
		var truth, null bool
		var integer, text, numeric string
		var small int16
		var medium int32
		var large, unsigned int64
		var floating float64
		var data []byte
		var when time.Time
		if err := rows.Scan(&truth, &integer, &small, &medium, &large, &unsigned, &numeric, &floating, &text, &data, &when, &null); err != nil {
			t.Fatal(err)
		}
		if !truth || !null || integer != "-9" || small != math.MinInt16 || medium != math.MinInt32 || large != math.MaxInt64 || unsigned != math.MaxUint32 || numeric != "18446744073709551615" || floating != -1.5 || text != "" || len(data) != 2 || data[0] != 1 || data[1] != 2 || !when.Equal(instant) {
			t.Fatal("fixed scalar conversion lost value")
		}
		rows.Close()
	})
}
