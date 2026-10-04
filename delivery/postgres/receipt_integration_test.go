//go:build integration

package postgres

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Borrowed receipt SQL is tested inside caller-owned real transactions. This
// does not certify provider authentication or the forthcoming public command.
func receiptFixture(t *testing.T) (context.Context, *pgxpool.Pool, *attemptStore, *receiptStore, delivery.ReceiptRecordRequest) {
	t.Helper()
	ctx, pool := intentDatabase(t)
	for _, sql := range []string{attemptSchemaSQL, stateSchemaSQL} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal("receipt schema", err)
		}
	}
	s, prepared := preparedFixture(t, false)
	seedIntentCommand(t, ctx, pool, prepared)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, s, []preparedIntent{prepared}, tx); err != nil {
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
		t.Fatal("claim", err)
	}
	if _, err := pool.Exec(ctx, receiptSchemaSQL); err != nil {
		t.Fatal("populated receipt migration", err)
	}
	var preserved bool
	if err := pool.QueryRow(ctx, `SELECT binding_aad=$1 AND ciphertext=$2 AND status_version=2 AND state='submitted' FROM identity.delivery_intents`, prepared.aad, prepared.envelope.Ciphertext).Scan(&preserved); err != nil || !preserved {
		t.Fatal("receipt migration changed populated custody or version", err)
	}
	q := delivery.ReceiptRecordRequest{TenantID: "tenant-a", IntentID: claim.Attempt.IntentID, Generation: 1, Provider: prepared.binding.Provider, ProviderEventID: "synthetic-provider-event-0001", Status: delivery.StateDelivered, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), IdempotencyKey: "synthetic-receipt-0001"}
	return ctx, pool, w, &receiptStore{deployment: "test", namespaceKey: [32]byte{1}}, q
}

func receiptTestSQL(tx pgx.Tx) cancellationSQL {
	return cancellationSQL{
		scan: func(ctx context.Context, query string, args []any, dest ...any) error {
			return tx.QueryRow(ctx, query, args...).Scan(dest...)
		},
		exec: func(ctx context.Context, query string, args ...any) error {
			_, err := tx.Exec(ctx, query, args...)
			return err
		},
	}
}

func applyTestReceipt(ctx context.Context, pool *pgxpool.Pool, s *receiptStore, q delivery.ReceiptRecordRequest, subject string) (delivery.ReceiptRecordResult, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	defer rollbackAttempt(tx)
	out, err := s.recordIn(ctx, receiptTestSQL(tx), q, subject)
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return delivery.ReceiptRecordResult{}, delivery.ErrOutcomeUnknown
	}
	return out, nil
}

func TestBorrowedReceiptTerminalReplayAndRollback(t *testing.T) {
	ctx, pool, worker, receipts, q := receiptFixture(t)
	tx := beginIntentTestTransaction(t, ctx, pool)
	provisional, err := receipts.recordIn(ctx, receiptTestSQL(tx), q, "user-a")
	if err != nil || !provisional.Advanced || provisional.State != delivery.StateDelivered {
		t.Fatal("receipt transition", err, provisional)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	var state string
	var erased bool
	if err := pool.QueryRow(ctx, `SELECT state,ciphertext IS NULL,(SELECT count(*) FROM identity.delivery_receipts) FROM identity.delivery_intents`).Scan(&state, &erased, &count); err != nil || state != "submitted" || erased || count != 0 {
		t.Fatal("rollback left receipt or effect", err)
	}
	out, err := applyTestReceipt(ctx, pool, receipts, q, "user-a")
	if err != nil || !out.Advanced || out.Deduplicated {
		t.Fatal("receipt commit", err, out)
	}
	again, err := applyTestReceipt(ctx, pool, receipts, q, "user-a")
	if err != nil || !again.Deduplicated || again.Advanced || again.State != delivery.StateDelivered {
		t.Fatal("original receipt replay", err, again)
	}
	if err := pool.QueryRow(ctx, `SELECT state,ciphertext IS NULL AND envelope_key_id IS NULL,(SELECT count(*) FROM identity.delivery_receipts) FROM identity.delivery_intents`).Scan(&state, &erased, &count); err != nil || state != "confirmed" || !erased || count != 1 {
		t.Fatal("receipt failed atomic erasure/dedupe", err)
	}
	// An old writer cannot overwrite the provider's terminal checkpoint.
	_, err = worker.Complete(ctx, delivery.CompleteRequest{TenantID: q.TenantID, IntentID: q.IntentID, Generation: q.Generation, WorkerID: "worker-a", Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateRejected, ObservedAt: q.ObservedAt}})
	if !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("late worker reversed receipt", err)
	}
	changed := q
	changed.Status = delivery.StateRejected
	if _, err := applyTestReceipt(ctx, pool, receipts, changed, "user-a"); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("changed event evidence replay", err)
	}
}

func TestBorrowedReceiptScopeOrderAndConcurrentDedupe(t *testing.T) {
	ctx, pool, _, receipts, q := receiptFixture(t)
	q.Status = delivery.StateAccepted
	start := make(chan struct{})
	var group sync.WaitGroup
	var winners atomic.Int32
	for range 8 {
		group.Go(func() {
			<-start
			out, err := applyTestReceipt(ctx, pool, receipts, q, "user-a")
			if err != nil {
				t.Error("concurrent receipt", err)
				return
			}
			if out.Advanced {
				winners.Add(1)
			}
		})
	}
	close(start)
	group.Wait()
	if winners.Load() != 1 {
		t.Fatal("event dedupe had multiple winners")
	}
	for _, change := range []func(*delivery.ReceiptRecordRequest){
		func(r *delivery.ReceiptRecordRequest) { r.Provider = "foreign-provider" },
		func(r *delivery.ReceiptRecordRequest) { r.TenantID = "tenant-other" },
		func(r *delivery.ReceiptRecordRequest) { r.Generation++; r.ProviderEventID = "fresh-stale-event" },
	} {
		bad := q
		change(&bad)
		if out, err := applyTestReceipt(ctx, pool, receipts, bad, "user-a"); err == nil || out != (delivery.ReceiptRecordResult{}) {
			t.Fatal("foreign/stale receipt admitted", out, err)
		}
	}
	if _, err := applyTestReceipt(ctx, pool, receipts, q, "user-other"); !errors.Is(err, delivery.ErrNotFound) {
		t.Fatal("foreign subject observed event", err)
	}
	q.ProviderEventID = "earlier-bounce"
	q.Status = delivery.StateBounced
	q.ObservedAt = q.ObservedAt.Add(-time.Second)
	stale, err := applyTestReceipt(ctx, pool, receipts, q, "user-a")
	if err != nil || stale.Advanced || stale.State != delivery.StateAccepted {
		t.Fatal("earlier callback reversed acceptance", err, stale)
	}
	q.ProviderEventID = "later-delivery"
	q.Status = delivery.StateDelivered
	q.ObservedAt = q.ObservedAt.Add(2 * time.Second)
	terminal, err := applyTestReceipt(ctx, pool, receipts, q, "user-a")
	if err != nil || !terminal.Advanced || terminal.State != delivery.StateDelivered {
		t.Fatal("later receipt did not settle acceptance", err, terminal)
	}
}

func TestBorrowedUnknownReceiptKeepsOriginalLiveCompletion(t *testing.T) {
	ctx, pool, worker, receipts, q := receiptFixture(t)
	q.Status = delivery.StateOutcomeUnknown
	if out, err := applyTestReceipt(ctx, pool, receipts, q, "user-a"); err != nil || !out.Advanced || out.State != delivery.StateOutcomeUnknown {
		t.Fatal("unknown checkpoint", err, out)
	}
	out, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: q.TenantID, IntentID: q.IntentID, Generation: 1, WorkerID: "worker-a", Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: q.ObservedAt}})
	if err != nil || out.State != delivery.StateDelivered {
		t.Fatal("unknown receipt discarded original live provider evidence", err, out)
	}
}

func TestBorrowedReceiptFailureRollsBackEffectsAndHistory(t *testing.T) {
	ctx, pool, _, receipts, q := receiptFixture(t)
	if _, err := pool.Exec(ctx, `ALTER TABLE identity.delivery_receipts ADD CONSTRAINT synthetic_receipt_failure CHECK(false) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if out, err := applyTestReceipt(ctx, pool, receipts, q, "user-a"); !errors.Is(err, delivery.ErrUnavailable) || out != (delivery.ReceiptRecordResult{}) {
		t.Fatal("failed receipt insert returned usable result", err, out)
	}
	var preserved bool
	if err := pool.QueryRow(ctx, `SELECT i.state='submitted' AND i.ciphertext IS NOT NULL AND i.status_version=2 AND p.lease_owner='worker-a' AND p.lease_until IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identity.delivery_receipts) FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)`).Scan(&preserved); err != nil || !preserved {
		t.Fatal("failure left a partial terminal effect or lost worker fence", err)
	}
}

func TestBorrowedReceiptWorkerReplayPrecisionAndImmutability(t *testing.T) {
	ctx, pool, worker, receipts, q := receiptFixture(t)
	completion := delivery.CompleteRequest{TenantID: q.TenantID, IntentID: q.IntentID, Generation: 1, WorkerID: "worker-a", Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: q.ObservedAt}}
	original, err := worker.Complete(ctx, completion)
	if err != nil {
		t.Fatal(err)
	}
	accepted := q
	accepted.Status = delivery.StateAccepted
	accepted.ObservedAt = accepted.ObservedAt.Add(100 * time.Nanosecond)
	if _, err := applyTestReceipt(ctx, pool, receipts, accepted, "user-a"); err != nil {
		t.Fatal(err)
	}
	// Distinct raw observations that collapse to one stored microsecond cannot
	// silently acquire an ordering from driver rounding or event digest order.
	q.ProviderEventID = "same-precision-delivery"
	q.ObservedAt = q.ObservedAt.Add(500 * time.Nanosecond)
	if _, err := applyTestReceipt(ctx, pool, receipts, q, "user-a"); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("timestamp rounding invented event order", err)
	}
	q.ObservedAt = q.ObservedAt.Add(time.Second)
	if _, err := applyTestReceipt(ctx, pool, receipts, q, "user-a"); err != nil {
		t.Fatal(err)
	}
	again, err := worker.Complete(ctx, completion)
	if err != nil || again != original {
		t.Fatal("provider receipt rewrote original worker completion replay", err, again)
	}
	for _, sql := range []string{`UPDATE identity.delivery_receipts SET advanced=false`, `DELETE FROM identity.delivery_receipts`, `TRUNCATE identity.delivery_receipts`} {
		if _, err := pool.Exec(ctx, sql); err == nil {
			t.Fatal("receipt history was mutable")
		}
	}
	q.IdempotencyKey = "different-receipt-command"
	if out, err := applyTestReceipt(ctx, pool, receipts, q, "user-a"); err != nil || !out.Deduplicated || out.Advanced || out.State != delivery.StateDelivered {
		t.Fatal("new command duplicated matching provider event", err, out)
	}
}

func TestBorrowedReceiptProviderCancellationAndNoResubmission(t *testing.T) {
	ctx, pool, worker, receipts, q := receiptFixture(t)
	q.Status = delivery.StateOutcomeUnknown
	if _, err := applyTestReceipt(ctx, pool, receipts, q, "user-a"); err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: q.TenantID, WorkerID: "worker-other"})
	if err != nil || claim.Claimed {
		t.Fatal("unknown callback authorized resubmission", err)
	}
	local, err := worker.cancel(ctx, delivery.CancelRequest{TenantID: q.TenantID, IntentID: q.IntentID, ExpectedGeneration: 1, Reason: "workflow-stop"}, "user-a")
	if err != nil || local.State != delivery.StateOutcomeUnknown || local.RemoteCancellationConfirmed {
		t.Fatal("local cancellation claimed remote result", err)
	}
	q.ProviderEventID = "confirmed-cancellation"
	q.Status = delivery.StateCancelled
	q.ObservedAt = q.ObservedAt.Add(time.Second)
	if out, err := applyTestReceipt(ctx, pool, receipts, q, "user-a"); err != nil || !out.Advanced || out.State != delivery.StateCancelled {
		t.Fatal("provider cancellation not applied", err, out)
	}
	var erased bool
	if err := pool.QueryRow(ctx, `SELECT state='cancelled' AND ciphertext IS NULL AND envelope_key_id IS NULL FROM identity.delivery_intents`).Scan(&erased); err != nil || !erased {
		t.Fatal("remote cancellation failed erasure", err)
	}
}

func TestBorrowedReceiptCrossEffectEventCollision(t *testing.T) {
	ctx, pool, worker, receipts, first := receiptFixture(t)
	store, prepared := preparedFixture(t, false)
	seedIntentCommand(t, ctx, pool, prepared)
	tx := beginIntentTestTransaction(t, ctx, pool)
	if err := persistInTestTransaction(ctx, store, []preparedIntent{prepared}, tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: first.TenantID, WorkerID: "worker-a"})
	if err != nil || !claim.Claimed || claim.Attempt.IntentID == first.IntentID {
		t.Fatal("second independent effect claim", err)
	}
	second := first
	second.IntentID = claim.Attempt.IntentID
	start := make(chan struct{})
	var group sync.WaitGroup
	var winners, conflicts atomic.Int32
	for _, request := range []delivery.ReceiptRecordRequest{first, second} {
		group.Go(func() {
			<-start
			out, err := applyTestReceipt(ctx, pool, receipts, request, "user-a")
			switch {
			case err == nil && out.Advanced && out.State == delivery.StateDelivered:
				winners.Add(1)
			case errors.Is(err, delivery.ErrConflict) && out == (delivery.ReceiptRecordResult{}):
				conflicts.Add(1)
			default:
				t.Error("cross-effect event result", err, out)
			}
		})
	}
	close(start)
	group.Wait()
	if winners.Load() != 1 || conflicts.Load() != 1 {
		t.Fatal("one provider event settled multiple effects", winners.Load(), conflicts.Load())
	}
	var preserved bool
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM identity.delivery_receipts)=1 AND
		(SELECT count(*) FROM identity.delivery_intents WHERE state='confirmed' AND ciphertext IS NULL)=1 AND
		(SELECT count(*) FROM identity.delivery_intents i JOIN identity.delivery_processing p USING(deployment,tenant_id,effect_id)
		 WHERE i.state='submitted' AND i.ciphertext IS NOT NULL AND i.envelope_key_id IS NOT NULL
		 AND i.status_version=2 AND p.lease_owner='worker-a' AND p.lease_until IS NOT NULL)=1`).Scan(&preserved); err != nil || !preserved {
		t.Fatal("event collision left loser effects or lost custody/worker fence", err)
	}
}
