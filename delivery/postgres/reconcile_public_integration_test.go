//go:build integration

package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	identitypostgres "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

type publicReconciliationQuerier struct {
	call func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error)
}

func (q *publicReconciliationQuerier) QueryOutcome(ctx context.Context, in delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
	return q.call(ctx, in)
}

func testPublicReconciliation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owned *database.Pool, service *EnqueueService, config EnqueueConfig, policy authorization.Service, templates []delivery.Template, enqueue EnqueueCommandRequest, first delivery.EnqueueResult, querier *publicReconciliationQuerier, permit *bool) {
	t.Helper()
	worker, err := service.policies.worker(1, service.reconciliation.codec)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: delivery.TenantID(enqueue.Binding.TenantID), WorkerID: "public-query-worker"})
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != first.IntentID {
		t.Fatal("query original claim", err)
	}
	if _, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, IntentID: claim.Attempt.IntentID, Generation: claim.Attempt.Generation, WorkerID: "public-query-worker", Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	op := ReconcileOperation()
	b := enqueue.Binding
	b.CommandID, _ = identity.NewCommandID()
	b.RecordID = string(first.IntentID)
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.ActorID = "query-service"
	b.ActorKind = authorization.SubjectServiceAccount
	scope := enqueue.ActorScope.Clone()
	scope.Request.Action = authorization.Action(op.OperationID)
	scope.Request.Subject.ID = authorization.SubjectID(b.ActorID)
	scope.Request.Subject.Kind = b.ActorKind
	request := ReconcileCommandRequest{Binding: b, ActorScope: scope, ExpectedStatusVersion: 3, Generation: 1}
	calls := 0
	nextCursor := "synthetic-private-provider-query-cursor"
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	current := delivery.OutcomeObservation{State: delivery.StateOutcomeUnknown, ObservedAt: observedAt, Checkpoint: nextCursor}
	expectedCursor := ""
	var queryError error
	querier.call = func(work context.Context, q delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		calls++
		if q.ProviderIdempotencyKey != string(first.IntentID) || q.ProviderIdempotencyKey == string(request.Binding.CommandID) || q.Checkpoint != expectedCursor || q.Generation != 1 {
			t.Fatal("query lost original key/scope/cursor")
		}
		// A separate connection must acquire both domain locks while the provider
		// callback is active, and no kernel execution row may exist for this query.
		tx, err := pool.Begin(work)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(work)
		if _, err := tx.Exec(work, `SELECT effect_id FROM identity.delivery_intents WHERE effect_id=$1 FOR UPDATE NOWAIT`, string(first.IntentID)); err != nil {
			t.Fatal("provider query held intent lock", err)
		}
		if _, err := tx.Exec(work, `SELECT effect_id FROM identity.delivery_processing WHERE effect_id=$1 FOR UPDATE NOWAIT`, string(first.IntentID)); err != nil {
			t.Fatal("provider query held processing lock", err)
		}
		id, _ := base64.RawURLEncoding.DecodeString(string(request.Binding.CommandID))
		var count int
		if err := pool.QueryRow(work, `SELECT count(*) FROM identity.commands WHERE tenant_id=$1 AND command_id=$2`, string(b.TenantID), id).Scan(&count); err != nil || count != 0 {
			t.Fatal("query reserved original kernel command before callback", err)
		}
		return current, queryError
	}
	*permit = false
	if _, err := service.Reconcile(ctx, request); !errors.Is(err, delivery.ErrForbidden) || calls != 0 {
		t.Fatal("denied query invoked provider", err)
	}
	*permit = true
	queryError = errors.New("synthetic-private-query-failure")
	if _, err := service.Reconcile(ctx, request); !errors.Is(err, delivery.ErrUnavailable) || strings.Contains(err.Error(), "private") {
		t.Fatal("query error leaked/fabricated evidence", err)
	}
	queryError = nil
	current.State, current.RetryAfter = delivery.StateTransientFailure, time.Second
	if _, err := service.Reconcile(ctx, request); !errors.Is(err, delivery.ErrUnavailable) {
		t.Fatal("unsupported transient query admitted retry/progress", err)
	}
	var cleanFailure bool
	if err := pool.QueryRow(ctx, `SELECT status_version=3 AND state='outcome-unknown' AND NOT EXISTS(SELECT 1 FROM identity.delivery_reconciliation_queries) AND NOT EXISTS(SELECT 1 FROM identity.delivery_reconciliation_cursors) FROM identity.delivery_intents WHERE effect_id=$1`, string(first.IntentID)).Scan(&cleanFailure); err != nil || !cleanFailure {
		t.Fatal("failed query persisted synthetic evidence", err)
	}
	current.State, current.RetryAfter = delivery.StateOutcomeUnknown, 0
	wrongActor := request
	wrongActor.Binding.ActorID = "unconfigured-service"
	wrongActor.ActorScope = scope.Clone()
	wrongActor.ActorScope.Request.Subject.ID = "unconfigured-service"
	if _, err := service.Reconcile(ctx, wrongActor); !errors.Is(err, delivery.ErrForbidden) || calls != 2 {
		t.Fatal("unconfigured actor queried", err)
	}
	successCalls := calls + 1
	initial, err := service.Reconcile(ctx, request)
	if err != nil || initial.State != delivery.StateOutcomeUnknown || initial.Retryable || initial.Checkpoint == "" || initial.Checkpoint == nextCursor || calls != successCalls {
		t.Fatal("first public query", err)
	}
	var wire []byte
	var status int
	if err := pool.QueryRow(ctx, `SELECT ciphertext FROM identity.delivery_reconciliation_cursors WHERE effect_id=$1`, string(first.IntentID)).Scan(&wire); err != nil || bytes.Contains(wire, []byte(nextCursor)) {
		t.Fatal("recoverable cursor absent/plaintext", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status_version FROM identity.delivery_intents WHERE effect_id=$1`, string(first.IntentID)).Scan(&status); err != nil || status != 4 {
		t.Fatal("query did not atomically advance status", err)
	}
	restarted, err := NewEnqueueService(ctx, owned, config, service.reconciliation.codec.service, policy, templates)
	if err != nil {
		t.Fatal(err)
	}
	if replay, err := restarted.Reconcile(ctx, request); err != nil || replay != initial || calls != successCalls {
		t.Fatal("restart replay queried or changed result", err)
	}
	changed := request
	changed.ExpectedStep = 1
	if _, err := restarted.Reconcile(ctx, changed); !errors.Is(err, delivery.ErrConflict) || calls != successCalls {
		t.Fatal("changed request replay admitted", err)
	}
	stale := request
	stale.Binding.CommandID, _ = identity.NewCommandID()
	if _, err := restarted.Reconcile(ctx, stale); !errors.Is(err, delivery.ErrConflict) || calls != successCalls {
		t.Fatal("stale fences queried", err)
	}
	// Use the real kernel reservation owner to simulate interruption before its
	// protected effect. Pending is not authorized absence, even after restart.
	pending := request
	pending.Binding.CommandID, _ = identity.NewCommandID()
	pending.ExpectedStatusVersion = 4
	pending.ExpectedStep = 1
	pending.Checkpoint = initial.Checkpoint
	progressScope := reconciliationCursorScope{Deployment: "test", Tenant: string(b.TenantID), Subject: string(b.UserID), Effect: string(first.IntentID), Provider: "test-provider", ProviderVersion: 1, Generation: 1, Step: 1}
	before := reconciliationCursorDigest(config.NamespaceKey, progressScope, nextCursor)
	prepared := reconciliationPrepared{request: reconciliationRequestDigest(restarted.keyed, pending, 1), query: [32]byte{1}, providerVersion: 1, state: delivery.StateOutcomeUnknown, observed: observedAt}
	q := delivery.ReceiptRecordRequest{TenantID: delivery.TenantID(b.TenantID), IntentID: first.IntentID, Provider: "test-provider", ProviderEventID: "synthetic-pending-query", Generation: 1, Status: delivery.StateOutcomeUnknown, ObservedAt: observedAt, IdempotencyKey: string(pending.Binding.CommandID)}
	command, err := newReconciliationQueryCommand(pending.Binding, q, 4, 1, before, [32]byte{}, restarted.reconciliation.native.store, prepared)
	if err != nil {
		t.Fatal(err)
	}
	coordinator, registry, native, err := restarted.reconciliation.build(&prepared)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := reconciliationQueryPlan(coordinator, registry, native, 1, pending.Binding, command, 4)
	if err != nil {
		t.Fatal(err)
	}
	reservation, _, err := coordinator.ReserveCommand(ctx, pending.Binding, command, plan)
	if err != nil || reservation == (identitypostgres.Reservation{}) {
		t.Fatal("pending original reservation", err)
	}
	if _, err := restarted.Reconcile(ctx, pending); !errors.Is(err, delivery.ErrOutcomeUnknown) || calls != successCalls {
		t.Fatal("pending command queried or manufactured replacement", err)
	}
	pendingQuery := identity.RecoveryQuery{CommandID: pending.Binding.CommandID, TenantID: pending.Binding.TenantID, UserID: pending.Binding.UserID, ActorID: pending.Binding.ActorID, ActorKind: pending.Binding.ActorKind, OperationID: pending.Binding.OperationID, RecordID: pending.Binding.RecordID}
	if record, err := restarted.RecoverReconciliation(ctx, pendingQuery, pending.ActorScope); err != nil || record.Outcome != identity.CommitOutcomeInProgress || calls != successCalls {
		t.Fatal("live recovery queried or replaced reservation", err)
	}
	id, _ := base64.RawURLEncoding.DecodeString(string(pending.Binding.CommandID))
	if _, err := pool.Exec(ctx, `UPDATE identity.commands SET lease_until=clock_timestamp()-interval '1 second' WHERE command_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if record, err := restarted.RecoverReconciliation(ctx, pendingQuery, pending.ActorScope); !errors.Is(err, delivery.ErrUnavailable) || record.Outcome != identity.CommitOutcomeNotCommitted || calls != successCalls {
		t.Fatal("abandoned recovery lost unanimous noncommit", err)
	}
	original := request
	// Both reads originate from the same progress snapshot. Only one original
	// kernel command may commit its successor; the loser cannot fork the cursor.
	savedQuery := querier.call
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	raceCursor := "synthetic-private-next-race-cursor"
	querier.call = func(work context.Context, q delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		if q.ProviderIdempotencyKey != string(first.IntentID) || q.Checkpoint != nextCursor {
			t.Error("concurrent query lost original snapshot")
		}
		started <- struct{}{}
		select {
		case <-release:
		case <-work.Done():
			return delivery.OutcomeObservation{}, work.Err()
		}
		return delivery.OutcomeObservation{State: delivery.StateOutcomeUnknown, ObservedAt: observedAt.Add(time.Millisecond), Checkpoint: raceCursor}, nil
	}
	var raced [2]delivery.ReconcileResult
	var raceErrors [2]error
	var group sync.WaitGroup
	for i := range 2 {
		candidate := pending
		candidate.Binding.CommandID, _ = identity.NewCommandID()
		group.Go(func() { raced[i], raceErrors[i] = restarted.Reconcile(ctx, candidate) })
	}
	barrier, stopBarrier := context.WithTimeout(ctx, 2*time.Second)
	for range 2 {
		select {
		case <-started:
		case <-barrier.Done():
			t.Error("two queries could not reach barrier", barrier.Err())
		}
	}
	close(release)
	group.Wait()
	stopBarrier()
	querier.call = savedQuery
	calls += 2
	var winner delivery.ReconcileResult
	wins := 0
	for i := range 2 {
		if raceErrors[i] == nil {
			winner = raced[i]
			wins++
		} else if !errors.Is(raceErrors[i], delivery.ErrConflict) {
			t.Fatal("concurrent loser unclassified", raceErrors[i])
		}
	}
	if wins != 1 || winner.State != delivery.StateOutcomeUnknown || winner.Checkpoint == "" || winner.Retryable {
		t.Fatal("concurrent checkpoint did not have one winner")
	}
	request.Binding.CommandID, _ = identity.NewCommandID()
	request.ExpectedStatusVersion = 5
	request.ExpectedStep = 2
	request.Checkpoint = winner.Checkpoint
	expectedCursor = raceCursor
	current = delivery.OutcomeObservation{State: delivery.StateDelivered, ObservedAt: observedAt.Add(2 * time.Millisecond)}
	// The provider was read outside the kernel reservation, but the downstream
	// lifecycle failure must roll back every projection/cursor/erasure together.
	if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages ADD CONSTRAINT public_query_failure CHECK(topic<>'delivery.reconciled.v1') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Reconcile(ctx, request); err == nil {
		t.Fatal("required lifecycle failure admitted query result")
	}
	var rolledBack bool
	if err := pool.QueryRow(ctx, `SELECT state='outcome-unknown' AND status_version=5 AND ciphertext IS NOT NULL AND (SELECT count(*) FROM identity.delivery_reconciliation_cursors WHERE effect_id=$1)=1 AND (SELECT count(*) FROM identity.delivery_reconciliation_queries)=2 AND (SELECT count(*) FROM identity.delivery_reconciliation_checkpoints)=2 FROM identity.delivery_intents WHERE effect_id=$1`, string(first.IntentID)).Scan(&rolledBack); err != nil || !rolledBack {
		t.Fatal("lifecycle rollback leaked query prefix", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages DROP CONSTRAINT public_query_failure`); err != nil {
		t.Fatal(err)
	}
	request.Binding.CommandID, _ = identity.NewCommandID()
	terminal, err := restarted.Reconcile(ctx, request)
	if err != nil || terminal.State != delivery.StateDelivered || terminal.Retryable || terminal.Checkpoint != "" || calls != successCalls+4 {
		t.Fatal("restart continuation did not settle", err)
	}
	var settled bool
	if err := pool.QueryRow(ctx, `SELECT state='confirmed' AND status_version=6 AND ciphertext IS NULL AND NOT EXISTS(SELECT 1 FROM identity.delivery_reconciliation_cursors WHERE effect_id=$1) AND (SELECT count(*) FROM identity.delivery_reconciliation_queries)=3 AND (SELECT count(*) FROM identity.delivery_attempt_history)=1 FROM identity.delivery_intents WHERE effect_id=$1`, string(first.IntentID)).Scan(&settled); err != nil || !settled {
		t.Fatal("terminal query lost atomic erasure/history", err)
	}
	if replay, err := restarted.Reconcile(ctx, original); err != nil || replay != initial || calls != successCalls+4 {
		t.Fatal("terminalization rewrote historical replay", err)
	}
	*permit = false
	if _, err := restarted.Reconcile(ctx, original); !errors.Is(err, delivery.ErrForbidden) || calls != successCalls+4 {
		t.Fatal("revoked policy disclosed replay", err)
	}
	*permit = true
	testPublicReconciliationCancellationAndExpiry(t, ctx, pool, restarted, enqueue, querier)
	testPublicReconciliationReceiptErasure(t, ctx, pool, restarted, enqueue, querier)
}

// The receipt participant does not own query cursors. This journey therefore
// proves the forward schema's shared cleanup owner, unlike query settlement's
// own explicit cursor deletion. Lifecycle failure must roll that deletion back.
func testPublicReconciliationReceiptErasure(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *EnqueueService, enqueue EnqueueCommandRequest, querier *publicReconciliationQuerier) {
	t.Helper()
	enqueue.Binding.CommandID, _ = identity.NewCommandID()
	enqueue.IdempotencyKey = "public-query-receipt-erasure"
	intent, err := service.Enqueue(ctx, enqueue)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := service.policies.worker(1, service.reconciliation.codec)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: delivery.TenantID(enqueue.Binding.TenantID), WorkerID: "query-receipt-worker"})
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != intent.IntentID {
		t.Fatal("receipt query original claim", err)
	}
	if _, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, IntentID: intent.IntentID, Generation: claim.Attempt.Generation, WorkerID: "query-receipt-worker", Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	b := enqueue.Binding
	op := ReconcileOperation()
	b.CommandID, _ = identity.NewCommandID()
	b.RecordID = string(intent.IntentID)
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.ActorID, b.ActorKind = "query-service", authorization.SubjectServiceAccount
	scope := enqueue.ActorScope.Clone()
	scope.Request.Action = authorization.Action(op.OperationID)
	scope.Request.Subject.ID, scope.Request.Subject.Kind = authorization.SubjectID(b.ActorID), b.ActorKind
	request := ReconcileCommandRequest{Binding: b, ActorScope: scope, ExpectedStatusVersion: 3, Generation: 1}
	calls := 0
	querier.call = func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		calls++
		return delivery.OutcomeObservation{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Checkpoint: "synthetic-receipt-private-cursor"}, nil
	}
	original, err := service.Reconcile(ctx, request)
	if err != nil || original.Checkpoint == "" || calls != 1 {
		t.Fatal("receipt query did not retain cursor", err)
	}
	var before []byte
	if err := pool.QueryRow(ctx, `SELECT ciphertext FROM identity.delivery_reconciliation_cursors WHERE effect_id=$1`, string(intent.IntentID)).Scan(&before); err != nil {
		t.Fatal(err)
	}
	receiptBinding := b
	receiptOp := ReceiptOperation()
	receiptBinding.CommandID, _ = identity.NewCommandID()
	receiptBinding.OperationID, receiptBinding.SchemaID, receiptBinding.SchemaVersion = receiptOp.OperationID, receiptOp.SchemaID, receiptOp.SchemaVersion
	receiptBinding.ActorID = "provider-actor"
	receiptScope := scope.Clone()
	receiptScope.Request.Action = authorization.Action(receiptOp.OperationID)
	receiptScope.Request.Subject.ID = "provider-actor"
	wire := map[string]any{"tenant_id": string(b.TenantID), "provider": "test-provider", "event_id": "synthetic-query-terminal-receipt", "intent_id": b.RecordID, "generation": uint32(1), "status": uint8(delivery.StateDelivered), "observed_at": time.Now().UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)}
	body, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	callback := SignedReceiptCallback{TenantID: delivery.TenantID(b.TenantID), Provider: "test-provider", ProviderConfigVersion: 1, KeyID: "callback-key", SignedAt: time.Now().UTC(), Body: body}
	callback.Signature = receiptAuthOracle(t, "test", [32]byte{9}, receiptSignedInput{Tenant: string(b.TenantID), Provider: callback.Provider, Version: 1, KeyID: callback.KeyID, SignedAt: callback.SignedAt, Body: callback.Body})
	receipt := ReceiptCommandRequest{Binding: receiptBinding, ActorScope: receiptScope, ExpectedStatusVersion: 4, Callback: callback}
	if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages ADD CONSTRAINT query_receipt_failure CHECK(topic<>'delivery.receipt-recorded.v1') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	failed := receipt
	failed.Binding.CommandID, _ = identity.NewCommandID()
	if got, err := service.RecordReceipt(ctx, failed); err == nil || got != (delivery.ReceiptRecordResult{}) {
		t.Fatal("failed receipt fabricated terminal query settlement", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages DROP CONSTRAINT query_receipt_failure`); err != nil {
		t.Fatal(err)
	}
	var preserved bool
	if err := pool.QueryRow(ctx, `SELECT state='outcome-unknown' AND ciphertext IS NOT NULL AND status_version=4 AND (SELECT ciphertext=$2::bytea FROM identity.delivery_reconciliation_cursors WHERE effect_id=$1) AND (SELECT count(*) FROM identity.delivery_receipts WHERE effect_id=$1)=1 FROM identity.delivery_intents WHERE effect_id=$1`, string(intent.IntentID), before).Scan(&preserved); err != nil || !preserved {
		t.Fatal("receipt lifecycle rollback lost original cursor", err)
	}
	if got, err := service.RecordReceipt(ctx, receipt); err != nil || got != (delivery.ReceiptRecordResult{Advanced: true, State: delivery.StateDelivered}) {
		t.Fatal("receipt did not settle query effect", err)
	}
	var erased bool
	if err := pool.QueryRow(ctx, `SELECT state='confirmed' AND ciphertext IS NULL AND status_version=5 AND NOT EXISTS(SELECT 1 FROM identity.delivery_reconciliation_cursors WHERE effect_id=$1) FROM identity.delivery_intents WHERE effect_id=$1`, string(intent.IntentID)).Scan(&erased); err != nil || !erased {
		t.Fatal("terminal receipt retained query cursor", err)
	}
	if replay, err := service.Reconcile(ctx, request); err != nil || replay != original || calls != 1 {
		t.Fatal("receipt settlement rewrote query replay or queried provider", err)
	}
}

func testPublicReconciliationCancellationAndExpiry(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *EnqueueService, enqueue EnqueueCommandRequest, querier *publicReconciliationQuerier) {
	t.Helper()
	enqueue.Binding.CommandID, _ = identity.NewCommandID()
	enqueue.IdempotencyKey = "public-query-expired-cancel"
	enqueue.ExpiresAt = time.Now().UTC().Truncate(time.Microsecond).Add(time.Second)
	intent, err := service.Enqueue(ctx, enqueue)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := service.policies.worker(1, service.reconciliation.codec)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: delivery.TenantID(enqueue.Binding.TenantID), WorkerID: "expired-query-worker"})
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != intent.IntentID {
		t.Fatal("expired-query original claim", err)
	}
	if _, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, IntentID: intent.IntentID, Generation: claim.Attempt.Generation, WorkerID: "expired-query-worker", Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC()}}); err != nil {
		t.Fatal(err)
	}
	b := enqueue.Binding
	op := ReconcileOperation()
	b.CommandID, _ = identity.NewCommandID()
	b.RecordID = string(intent.IntentID)
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.ActorID = "query-service"
	b.ActorKind = authorization.SubjectServiceAccount
	scope := enqueue.ActorScope.Clone()
	scope.Request.Action = authorization.Action(op.OperationID)
	scope.Request.Subject.ID = authorization.SubjectID(b.ActorID)
	scope.Request.Subject.Kind = b.ActorKind
	r := ReconcileCommandRequest{Binding: b, ActorScope: scope, ExpectedStatusVersion: 3, Generation: 1}
	calls := 0
	observation := delivery.OutcomeObservation{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), Checkpoint: "synthetic-cancel-progress"}
	querier.call = func(work context.Context, q delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		calls++
		if q.IntentID != intent.IntentID || q.ProviderIdempotencyKey != string(intent.IntentID) {
			t.Fatal("expired query changed original effect")
		}
		return observation, nil
	}
	// Wait on this task-owned database clock, not an unbounded application timer.
	// Neither expiry nor an old bearer may fabricate remote cancellation.
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(GREATEST(EXTRACT(EPOCH FROM($1::timestamptz-clock_timestamp()))+0.01,0))`, enqueue.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	unknown, err := service.Reconcile(ctx, r)
	if err != nil || unknown.State != delivery.StateOutcomeUnknown || unknown.Retryable || calls != 1 {
		t.Fatal("expired effect lookup denied/invented retry", err)
	}
	// A provider's cancelled result is not admissible before local cancellation
	// is pending. No command/progress successor may be created by that evidence.
	r.Binding.CommandID, _ = identity.NewCommandID()
	r.ExpectedStatusVersion = 4
	r.ExpectedStep = 1
	r.Checkpoint = unknown.Checkpoint
	observation.State = delivery.StateCancelled
	observation.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	observation.Checkpoint = ""
	if _, err := service.Reconcile(ctx, r); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("remote cancellation admitted without pending transition", err)
	}
	cb := enqueue.Binding
	cancelOp := CancelOperation()
	cb.CommandID, _ = identity.NewCommandID()
	cb.RecordID = string(intent.IntentID)
	cb.OperationID, cb.SchemaID, cb.SchemaVersion = cancelOp.OperationID, cancelOp.SchemaID, cancelOp.SchemaVersion
	cancelScope := enqueue.ActorScope.Clone()
	cancelScope.Request.Action = authorization.Action(cancelOp.OperationID)
	local, err := service.Cancel(ctx, CancelCommandRequest{Binding: cb, ActorScope: cancelScope, ExpectedStatusVersion: 4, Request: delivery.CancelRequest{TenantID: delivery.TenantID(b.TenantID), IntentID: intent.IntentID, ExpectedGeneration: 1, Reason: "workflow-cancel"}})
	if err != nil || local.State != delivery.StateOutcomeUnknown || local.RemoteCancellationConfirmed {
		t.Fatal("local stop fabricated remote cancellation", err)
	}
	r.Binding.CommandID, _ = identity.NewCommandID()
	r.ExpectedStatusVersion = 5
	settled, err := service.Reconcile(ctx, r)
	if err != nil || settled.State != delivery.StateCancelled || settled.Retryable || calls != 3 {
		t.Fatal("pending expired cancellation did not settle", err)
	}
	var terminal bool
	if err := pool.QueryRow(ctx, `SELECT state='cancelled' AND ciphertext IS NULL AND status_version=6 AND NOT EXISTS(SELECT 1 FROM identity.delivery_reconciliation_cursors WHERE effect_id=$1) AND (SELECT count(*) FROM identity.delivery_attempt_history WHERE effect_id=$1)=1 FROM identity.delivery_intents WHERE effect_id=$1`, string(intent.IntentID)).Scan(&terminal); err != nil || !terminal {
		t.Fatal("cancellation lost erasure/history", err)
	}
}
