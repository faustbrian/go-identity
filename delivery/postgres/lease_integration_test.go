//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

func claimedLeaseFixture(t *testing.T, remaining time.Duration) (context.Context, *pgxpool.Pool, *attemptStore, delivery.ClaimResult, leaseFence) {
	t.Helper()
	ctx, pool := intentDatabase(t)
	if _, err := pool.Exec(ctx, attemptSchemaSQL); err != nil {
		t.Fatal(err)
	}
	s, p := preparedFixtureExpiry(t, false, remaining)
	seedIntentCommand(t, ctx, pool, p)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{p}, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	w, err := newAttemptStore(pool, "test", s.codec, delivery.DefaultConfig(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := w.Claim(ctx, delivery.ClaimRequest{TenantID: "tenant-a", WorkerID: "worker-a"})
	if err != nil || !claim.Claimed {
		t.Fatal("initial claim", err)
	}
	return ctx, pool, w, claim, leaseFence{TenantID: claim.Attempt.TenantID, IntentID: claim.Attempt.IntentID, WorkerID: "worker-a", Generation: claim.Attempt.Generation}
}

func TestDurableLeaseRenewalKeepsOriginalBounds(t *testing.T) {
	for _, remaining := range []time.Duration{5 * time.Second, time.Hour} {
		t.Run(remaining.String(), func(t *testing.T) {
			ctx, pool, w, claim, fence := claimedLeaseFixture(t, remaining)
			var started, before time.Time
			if err := pool.QueryRow(ctx, `SELECT started_at,clock_timestamp() FROM identity.delivery_attempt_history`).Scan(&started, &before); err != nil {
				t.Fatal(err)
			}
			until, err := w.Renew(ctx, fence)
			if err != nil || until.Before(claim.LeaseUntil) || until.After(claim.Attempt.ValidUntil) || until.After(started.Add(time.Minute)) || until.Before(before) {
				t.Fatal("renewal changed original lifetime or lost ownership", err)
			}
			var recorded, historical time.Time
			var generation, attempts int
			if err := pool.QueryRow(ctx, `SELECT p.lease_until,h.lease_until,p.generation,p.attempt_number FROM identity.delivery_processing p JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id,generation)`).Scan(&recorded, &historical, &generation, &attempts); err != nil || !recorded.Equal(until) || !historical.Equal(until) || generation != 1 || attempts != 1 {
				t.Fatal("heartbeat created another attempt or lost durable deadline", err)
			}
			if remaining < time.Minute && !until.Equal(claim.Attempt.ValidUntil) {
				t.Fatalf("renewal did not retain exact credential expiry: remaining delta %s", claim.Attempt.ValidUntil.Sub(until))
			}
			// Move the retained original start near its absolute lifetime cap.
			// No clock injection or application time supplies renewal authority.
			if remaining > time.Minute {
				if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET lease_until=clock_timestamp()+INTERVAL '1 second'`); err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(ctx, `UPDATE identity.delivery_attempt_history SET started_at=clock_timestamp()-INTERVAL '55 seconds',lease_until=clock_timestamp()+INTERVAL '1 second' RETURNING started_at`); err != nil {
					t.Fatal(err)
				}
				if err := pool.QueryRow(ctx, `SELECT started_at FROM identity.delivery_attempt_history`).Scan(&started); err != nil {
					t.Fatal(err)
				}
				until, err = w.Renew(ctx, fence)
				if err != nil || !until.Equal(started.Add(time.Minute)) {
					t.Fatal("heartbeat reset first-attempt origin", err)
				}
			}
		})
	}
}

func TestDurableLeaseForeignExpiredAndChangedPolicyDenied(t *testing.T) {
	ctx, pool, w, claim, fence := claimedLeaseFixture(t, time.Hour)
	for _, bad := range []leaseFence{
		{TenantID: "tenant-other", IntentID: fence.IntentID, WorkerID: fence.WorkerID, Generation: 1},
		{TenantID: fence.TenantID, IntentID: fence.IntentID, WorkerID: "worker-other", Generation: 1},
		{TenantID: fence.TenantID, IntentID: fence.IntentID, WorkerID: fence.WorkerID, Generation: 2},
	} {
		if _, err := w.Renew(ctx, bad); !errors.Is(err, delivery.ErrConflict) {
			t.Fatal("foreign heartbeat accepted", err)
		}
		if _, err := w.Release(ctx, bad); !errors.Is(err, delivery.ErrConflict) {
			t.Fatal("foreign release accepted", err)
		}
	}
	config := delivery.DefaultConfig()
	config.SenderTimeout = time.Second
	changed, err := newAttemptStore(pool, "test", w.codec, config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changed.Renew(ctx, fence); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("replacement policy renewed an original attempt", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := w.Renew(cancelled, fence); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled heartbeat continued", err)
	}
	if _, err := w.Release(cancelled, fence); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled release continued", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET lease_until=clock_timestamp()-INTERVAL '1 second'`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Renew(ctx, fence); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("expired heartbeat resurrected lease", err)
	}
	if _, err := w.Release(ctx, fence); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("expired release bypassed fence", err)
	}
	if c, err := w.Claim(ctx, delivery.ClaimRequest{TenantID: fence.TenantID, WorkerID: "replacement"}); err != nil || c.Claimed {
		t.Fatal("expired potentially invoked effect was resubmitted", err)
	}
	var until time.Time
	if err := pool.QueryRow(ctx, `SELECT lease_until FROM identity.delivery_attempt_history`).Scan(&until); err != nil || !until.Equal(claim.LeaseUntil) {
		t.Fatal("denied heartbeat changed original history", err)
	}
}

func TestDurableLeaseReleaseIsReplayableUnknownNotRetry(t *testing.T) {
	ctx, pool, w, _, fence := claimedLeaseFixture(t, time.Hour)
	result, err := w.Release(ctx, fence)
	if err != nil || result.Commit != delivery.CommitCommitted || result.State != delivery.StateOutcomeUnknown {
		t.Fatal("release fabricated provider outcome", err)
	}
	for range 2 {
		if replay, err := w.Release(ctx, fence); err != nil || replay != result {
			t.Fatal("exact release did not recover recorded result", err)
		}
		if c, err := w.Claim(ctx, delivery.ClaimRequest{TenantID: fence.TenantID, WorkerID: "replacement"}); err != nil || c.Claimed {
			t.Fatal("release allowed blind provider retry", err)
		}
	}
	if _, err := w.Renew(ctx, fence); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("released invocation renewed", err)
	}
	var unknown, noLease, retained bool
	if err := pool.QueryRow(ctx, `SELECT i.state='outcome-unknown',p.lease_owner IS NULL AND p.lease_until IS NULL AND p.next_attempt_at IS NULL,i.ciphertext IS NOT NULL FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&unknown, &noLease, &retained); err != nil || !unknown || !noLease || !retained {
		t.Fatal("release lost recovery custody or retained retry authority", err)
	}
}

func TestDurableLeaseRenewalRacesCompletionWithoutResurrection(t *testing.T) {
	ctx, pool, w, _, fence := claimedLeaseFixture(t, time.Hour)
	start := make(chan struct{})
	var group sync.WaitGroup
	var renewed error
	var completion delivery.CompleteResult
	var completed error
	group.Go(func() { <-start; _, renewed = w.Renew(ctx, fence) })
	group.Go(func() {
		<-start
		completion, completed = w.Complete(ctx, delivery.CompleteRequest{TenantID: fence.TenantID, IntentID: fence.IntentID, WorkerID: fence.WorkerID, Generation: fence.Generation, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}})
	})
	close(start)
	group.Wait()
	if renewed != nil && !errors.Is(renewed, delivery.ErrConflict) || completed != nil || completion.State != delivery.StateDelivered {
		t.Fatal("heartbeat/completion race lost terminal outcome", renewed, completed)
	}
	if _, err := w.Renew(ctx, fence); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("terminal invocation resurrected", err)
	}
	if _, err := w.Release(ctx, fence); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("release overwrote delivered evidence", err)
	}
	var terminal bool
	if err := pool.QueryRow(ctx, `SELECT i.state='confirmed' AND i.ciphertext IS NULL AND p.lease_owner IS NULL AND p.lease_until IS NULL FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&terminal); err != nil || !terminal {
		t.Fatal("completion/heartbeat durable state inconsistent", err)
	}
}

func TestDurableLeaseOldGenerationCannotChangeReplacement(t *testing.T) {
	ctx, pool, w, _, first := claimedLeaseFixture(t, time.Hour)
	if result, err := w.Complete(ctx, first.completion()); err != nil || result.State != delivery.StateRetryWait {
		t.Fatal("proven no invocation did not follow bounded retry policy", err)
	}
	// Advance the database-owned due schedule, not any worker clock.
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET next_attempt_at=clock_timestamp()-INTERVAL '1 second'`); err != nil {
		t.Fatal(err)
	}
	claim, err := w.Claim(ctx, delivery.ClaimRequest{TenantID: first.TenantID, WorkerID: "replacement"})
	if err != nil || !claim.Claimed || claim.Attempt.Generation != 2 {
		t.Fatal("replacement attempt", err)
	}
	if _, err := w.Renew(ctx, first); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("old generation renewed replacement", err)
	}
	if _, err := w.Release(ctx, first); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("old generation released replacement", err)
	}
	second := leaseFence{TenantID: first.TenantID, IntentID: first.IntentID, WorkerID: "replacement", Generation: 2}
	if _, err := w.Renew(ctx, second); err != nil {
		t.Fatal("replacement lost valid ownership", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_processing SET cancel_requested=true`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Renew(ctx, second); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("cancel-requested invocation prolonged", err)
	}
	// Cancellation cannot turn uncertain provider effects into local success.
	if result, err := w.Release(ctx, second); err != nil || result.State != delivery.StateOutcomeUnknown {
		t.Fatal("cancellation fabricated provider prevention", err)
	}
}

func TestDurableLeaseRejectsInvalidInputsWithoutDatabase(t *testing.T) {
	var w *attemptStore
	for _, f := range []leaseFence{
		{},
		{TenantID: "tenant", IntentID: "synthetic-intent-0001", WorkerID: "worker"},
		{TenantID: "tenant", IntentID: "short", WorkerID: "worker", Generation: 1},
		{TenantID: "tenant", IntentID: "synthetic-intent-0001", WorkerID: "", Generation: 1},
	} {
		if until, err := w.Renew(context.Background(), f); !errors.Is(err, delivery.ErrInvalidInput) || !until.IsZero() {
			t.Fatal("invalid heartbeat admitted", err)
		}
		if result, err := w.Release(context.Background(), f); !errors.Is(err, delivery.ErrInvalidInput) || result != (delivery.CompleteResult{}) {
			t.Fatal("invalid release admitted", err)
		}
	}
	f := leaseFence{TenantID: "tenant", IntentID: "synthetic-intent-0001", WorkerID: "worker", Generation: 1}
	if _, err := w.Renew(context.Background(), f); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("nil owner heartbeat", err)
	}
	if _, err := w.Release(context.Background(), f); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("nil owner release", err)
	}
}
