//go:build integration

package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

func checkpointFixture(t *testing.T) (context.Context, *pgxpool.Pool, *receiptStore, delivery.ReceiptRecordRequest) {
	t.Helper()
	ctx, pool, worker, receipts, q := receiptFixture(t)
	if _, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: q.TenantID, IntentID: q.IntentID, Generation: 1, WorkerID: "worker-a", Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: q.ObservedAt}}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, reconciliationSchemaSQL); err != nil {
		t.Fatal("populated reconciliation migration", err)
	}
	return ctx, pool, receipts, q
}

func commitCheckpoint(ctx context.Context, pool *pgxpool.Pool, s *receiptStore, q delivery.ReceiptRecordRequest, step int64, before, after [32]byte) (delivery.ReceiptRecordResult, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	defer rollbackAttempt(tx)
	out, err := s.reconcileIn(ctx, receiptTestSQL(tx), q, "user-a", step, before, after)
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return delivery.ReceiptRecordResult{}, delivery.ErrOutcomeUnknown
	}
	return out, nil
}

func TestReconciliationCheckpointAtomicityAndImmutableReplay(t *testing.T) {
	ctx, pool, store, q := checkpointFixture(t)
	first, next := [32]byte{1}, [32]byte{2}
	q.Status = delivery.StateOutcomeUnknown
	tx := beginIntentTestTransaction(t, ctx, pool)
	if _, err := store.reconcileIn(ctx, receiptTestSQL(tx), q, "user-a", 0, [32]byte{}, first); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM identity.delivery_reconciliation_checkpoints)+(SELECT count(*) FROM identity.delivery_receipts)`).Scan(&rows); err != nil || rows != 0 {
		t.Fatal("rollback advanced checkpoint", err)
	}
	if got, err := commitCheckpoint(ctx, pool, store, q, 0, [32]byte{}, first); err != nil || got.State != delivery.StateOutcomeUnknown {
		t.Fatal("first checkpoint", err)
	}
	terminal := q
	terminal.ProviderEventID, terminal.Status, terminal.ObservedAt = "synthetic-query-terminal", delivery.StateDelivered, q.ObservedAt.Add(time.Second)
	if got, err := commitCheckpoint(ctx, pool, store, terminal, 1, first, next); err != nil || got.State != delivery.StateDelivered || !got.Advanced {
		t.Fatal("terminal checkpoint", err)
	}
	if got, err := commitCheckpoint(ctx, pool, store, q, 0, [32]byte{}, first); err != nil || !got.Deduplicated || got.State != delivery.StateOutcomeUnknown {
		t.Fatal("original query replay returned later state", err)
	}
	if _, err := commitCheckpoint(ctx, pool, store, q, 0, [32]byte{}, next); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("changed cursor replay", err)
	}
	if _, err := commitCheckpoint(ctx, pool, store, q, 1, [32]byte{}, first); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("changed checkpoint step replay", err)
	}
	var preserved bool
	if err := pool.QueryRow(ctx, `SELECT i.state='confirmed' AND i.ciphertext IS NULL AND h.outcome=$1 AND (SELECT count(*) FROM identity.delivery_reconciliation_checkpoints)=2 FROM identity.delivery_intents i JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id)`, int16(delivery.StateOutcomeUnknown)).Scan(&preserved); err != nil || !preserved {
		t.Fatal("checkpoint changed original history or lost terminal erasure", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE identity.delivery_reconciliation_checkpoints SET step=step`); err == nil {
		t.Fatal("checkpoint mutable")
	}
}

func TestReconciliationCheckpointFencesAndClosure(t *testing.T) {
	ctx, pool, store, q := checkpointFixture(t)
	q.Status = delivery.StateOutcomeUnknown
	first := [32]byte{1}
	if _, err := commitCheckpoint(ctx, pool, store, q, 0, [32]byte{}, first); err != nil {
		t.Fatal(err)
	}
	second := q
	second.ProviderEventID, second.ObservedAt = "synthetic-query-next", q.ObservedAt.Add(time.Second)
	if _, err := commitCheckpoint(ctx, pool, store, second, 0, [32]byte{}, first); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("stale checkpoint advanced", err)
	}
	second.Generation = 2
	if _, err := commitCheckpoint(ctx, pool, store, second, 0, [32]byte{}, first); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("stale generation advanced", err)
	}
	second.Generation = 1
	if _, err := commitCheckpoint(ctx, pool, store, second, 1, first, [32]byte{}); err != nil {
		t.Fatal("close checkpoint", err)
	}
	third := second
	third.ProviderEventID, third.ObservedAt = "synthetic-query-after-close", second.ObservedAt.Add(time.Second)
	if _, err := commitCheckpoint(ctx, pool, store, third, 0, [32]byte{}, first); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("closed query sequence resurrected", err)
	}
	if got, err := commitCheckpoint(ctx, pool, store, second, 1, first, [32]byte{}); err != nil || !got.Deduplicated {
		t.Fatal("closed sequence exact replay", err)
	}
	// Cursor exhaustion ends only a query sequence. An unresolved effect must
	// support a separately fenced later poll in this same attempt generation.
	third.ProviderEventID = "synthetic-new-poll-after-cursor-end"
	third.Status = delivery.StateDelivered
	if got, err := commitCheckpoint(ctx, pool, store, third, 2, [32]byte{}, [32]byte{}); err != nil || got.State != delivery.StateDelivered {
		t.Fatal("cursor exhaustion permanently blocked unknown-effect polling", err)
	}
}

func TestReconciliationCheckpointSerializesConcurrentProgress(t *testing.T) {
	ctx, pool, store, q := checkpointFixture(t)
	q.Status = delivery.StateOutcomeUnknown
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for n := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			candidate := q
			candidate.ProviderEventID = fmt.Sprintf("synthetic-concurrent-query-%d", n)
			_, err := commitCheckpoint(ctx, pool, store, candidate, 0, [32]byte{}, [32]byte{byte(n + 1)})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	committed := 0
	for err := range errs {
		if err == nil {
			committed++
		} else if !errors.Is(err, delivery.ErrConflict) {
			t.Fatal("query race", err)
		}
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_reconciliation_checkpoints`).Scan(&count); err != nil || count != 1 || committed != 1 {
		t.Fatal("concurrent query forked checkpoint", err, count, committed)
	}
}

func TestReconciliationCheckpointRejectsLiveInvocation(t *testing.T) {
	ctx, pool, _, store, q := receiptFixture(t)
	if _, err := pool.Exec(ctx, reconciliationSchemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := commitCheckpoint(ctx, pool, store, q, 0, [32]byte{}, [32]byte{1}); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("query superseded live invocation", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.delivery_receipts`).Scan(&count); err != nil || count != 0 {
		t.Fatal("live invocation changed", err)
	}
}
