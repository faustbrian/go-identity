//go:build integration

package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Observe actual downstream exclusion before crossing the primary deadline.
// Cancellation, rollback and joining own the worker on every failure path.
func waitConsumingExpiry(t *testing.T, ctx context.Context, db *pgx.Conn, deadline time.Time, run func(context.Context) error, unlock func() error) {
	t.Helper()
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	joined := false
	defer func() {
		cancel()
		_ = unlock()
		if !joined {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("native consuming worker did not stop")
			}
		}
	}()
	go func() { done <- run(runCtx) }()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%otp_store%challenges%FOR UPDATE%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			joined = true
			t.Fatal("consuming submission did not reach challenge exclusion", err)
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	for {
		var now time.Time
		if err := db.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
			t.Fatal(err)
		}
		if !now.Before(deadline) {
			break
		}
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		joined = true
		if err == nil {
			t.Fatal("expired original eligibility admitted after lock wait")
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}
