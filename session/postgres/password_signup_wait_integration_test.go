//go:build integration

package postgres

import (
	"context"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"testing"
	"time"
)

func applySignupAfterPreAuthWait(t *testing.T, ctx context.Context, pool *database.Pool, coordinator *kernel.Coordinator, w kernel.Work, command identity.Command, tenant identity.TenantID, flow identity.PreAuthTransactionID, deadline time.Time) (identity.CommandResult, error) {
	t.Helper()
	lock, err := pool.Raw().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = lock.Rollback(cleanup)
	}()
	if _, err := lock.Exec(ctx, `UPDATE session_store.preauth_transactions SET version=version WHERE tenant_id=$1 AND flow_id=$2`, string(tenant), string(flow)); err != nil {
		t.Fatal(err)
	}
	bounded, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	type applied struct {
		result identity.CommandResult
		err    error
	}
	completed := make(chan applied, 1)
	go func() {
		result, err := coordinator.ApplyFeature(bounded, w, command)
		completed <- applied{result, err}
	}()
	joined := false
	defer func() {
		if !joined {
			stop()
			<-completed
		}
	}()
	// Observe the actual pre-auth row-lock wait, then primary time crossing the
	// original deadline. No sleep is used as evidence that the writer blocked.
	for blocked, expired := false, false; !blocked || !expired; {
		var waiting bool
		// Separate autocommit observations avoid retaining the lock owner's
		// initial statistics snapshot across the polling transaction.
		if err := pool.Raw().QueryRow(bounded, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%session_store%.preauth_transactions%'),clock_timestamp()>$1`, deadline).Scan(&waiting, &expired); err != nil {
			t.Fatal("signup pre-auth lock/deadline barrier", err)
		}
		blocked = blocked || waiting
		if !blocked || !expired {
			timer := time.NewTimer(time.Millisecond)
			select {
			case <-timer.C:
			case <-bounded.Done():
			}
			timer.Stop()
		}
	}
	if err := lock.Commit(bounded); err != nil {
		t.Fatal(err)
	}
	got := <-completed
	joined = true
	return got.result, got.err
}
