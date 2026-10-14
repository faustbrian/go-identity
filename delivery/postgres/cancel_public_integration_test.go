//go:build integration

package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testAuthenticatedCancellation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *EnqueueService, enqueue EnqueueCommandRequest, permit *bool) {
	t.Helper()
	for _, noop := range []bool{false, true} {
		q := enqueue
		q.Binding.CommandID, _ = identity.NewCommandID()
		q.IdempotencyKey = "public-cancel-sendable"
		if noop {
			q.NoOpEquivalent, q.IdentifierID, q.IdempotencyKey = true, "", "public-cancel-noop"
		}
		admitted, err := service.Enqueue(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		statusScope := q.ActorScope.Clone()
		statusScope.Request.Action = "identity.delivery.status-get"
		snapshot, err := service.VersionedStatusGet(ctx, delivery.StatusGetRequest{TenantID: delivery.TenantID(q.Binding.TenantID), IntentID: admitted.IntentID}, q.Binding.UserID, statusScope)
		if err != nil {
			t.Fatal(err)
		}
		b := q.Binding
		b.CommandID, _ = identity.NewCommandID()
		b.RecordID = string(admitted.IntentID)
		op := cancelOperation()
		b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
		caller := q.ActorScope.Clone()
		caller.Request.Action = "identity.delivery.cancel"
		request := CancelCommandRequest{Binding: b, ActorScope: caller, ExpectedStatusVersion: snapshot.StatusVersion, Request: delivery.CancelRequest{TenantID: delivery.TenantID(b.TenantID), IntentID: admitted.IntentID, ExpectedGeneration: snapshot.Status.AttemptGeneration, Reason: "synthetic-private-reason"}}
		var baseline int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE purpose='identity.delivery.cancel'`).Scan(&baseline); err != nil {
			t.Fatal(err)
		}
		*permit = false
		if got, err := service.Cancel(ctx, request); !errors.Is(err, delivery.ErrForbidden) || got != (delivery.CancelResult{}) {
			t.Fatal("denied cancellation disclosed result", err)
		}
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE purpose='identity.delivery.cancel'`).Scan(&count); err != nil || count != baseline {
			t.Fatal("denied cancellation reserved a command", err)
		}
		*permit = true
		failed := request
		failed.Binding.CommandID, _ = identity.NewCommandID()
		if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages ADD CONSTRAINT public_cancel_failure CHECK (topic<>'delivery.cancelled.v1') NOT VALID`); err != nil {
			t.Fatal(err)
		}
		if got, err := service.Cancel(ctx, failed); err == nil || got != (delivery.CancelResult{}) {
			t.Fatal("downstream cancellation failure reported success", err)
		}
		if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages DROP CONSTRAINT public_cancel_failure`); err != nil {
			t.Fatal(err)
		}
		unchanged, err := service.VersionedStatusGet(ctx, delivery.StatusGetRequest{TenantID: request.Request.TenantID, IntentID: request.Request.IntentID}, b.UserID, statusScope)
		if err != nil || unchanged != snapshot {
			t.Fatal("downstream failure retained a local cancellation prefix", err)
		}
		got, err := service.Cancel(ctx, request)
		want := delivery.CancelResult{State: delivery.StateCancelled, LocalCancelled: true}
		if err != nil || got != want {
			t.Fatal("public cancellation failed", err, got)
		}
		replay, err := service.Cancel(ctx, request)
		if err != nil || replay != want {
			t.Fatal("original public cancellation replay lost result", err, replay)
		}
		var version uint64
		if err := pool.QueryRow(ctx, `SELECT status_version FROM identity.delivery_intents WHERE deployment='test' AND effect_id=$1`, b.RecordID).Scan(&version); err != nil || version != snapshot.StatusVersion+1 {
			t.Fatal("public replay renewed mutation fence", err)
		}
		changed := request
		changed.Request.Reason = "changed-confidential-reason"
		if got, err := service.Cancel(ctx, changed); !errors.Is(err, delivery.ErrConflict) || got != (delivery.CancelResult{}) {
			t.Fatal("changed cancellation replay accepted", err)
		}
		stale := request
		stale.Binding.CommandID, _ = identity.NewCommandID()
		if got, err := service.Cancel(ctx, stale); !errors.Is(err, delivery.ErrConflict) || got != (delivery.CancelResult{}) {
			t.Fatal("fresh command reused stale status fence", err)
		}
		*permit = false
		if got, err := service.Cancel(ctx, request); !errors.Is(err, delivery.ErrForbidden) || got != (delivery.CancelResult{}) {
			t.Fatal("historical cancellation bypassed current policy", err)
		}
		*permit = true
	}
}

func testSubmittedCancellation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *EnqueueService, q EnqueueCommandRequest) {
	t.Helper()
	q.Binding.CommandID, _ = identity.NewCommandID()
	q.IdempotencyKey, q.ProviderConfigVersion = "public-cancel-submitted", 2
	admitted, err := service.Enqueue(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := service.policies.worker(2, service.executor.custody.store.codec)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: delivery.TenantID(q.Binding.TenantID), WorkerID: "cancel-worker"})
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != admitted.IntentID {
		t.Fatal("retained-policy worker did not claim target", err)
	}
	statusScope := q.ActorScope.Clone()
	statusScope.Request.Action = "identity.delivery.status-get"
	snapshot, err := service.VersionedStatusGet(ctx, delivery.StatusGetRequest{TenantID: claim.Attempt.TenantID, IntentID: admitted.IntentID}, q.Binding.UserID, statusScope)
	if err != nil {
		t.Fatal(err)
	}
	b := q.Binding
	b.CommandID, _ = identity.NewCommandID()
	b.RecordID = string(admitted.IntentID)
	op := cancelOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	caller := q.ActorScope.Clone()
	caller.Request.Action = "identity.delivery.cancel"
	request := CancelCommandRequest{Binding: b, ActorScope: caller, ExpectedStatusVersion: snapshot.StatusVersion, Request: delivery.CancelRequest{TenantID: claim.Attempt.TenantID, IntentID: admitted.IntentID, ExpectedGeneration: 1, Reason: "synthetic-submitted-stop"}}
	want := delivery.CancelResult{State: delivery.StateOutcomeUnknown, LocalCancelled: true}
	if got, err := service.Cancel(ctx, request); err != nil || got != want {
		t.Fatal("submitted public cancellation lost policy or claimed remote success", err, got)
	}
	completed, err := worker.Complete(ctx, delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, IntentID: admitted.IntentID, WorkerID: "cancel-worker", Generation: 1, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}})
	if err != nil || completed.State != delivery.StateDelivered {
		t.Fatal("public cancellation destroyed live provider completion", err)
	}
	if got, err := service.Cancel(ctx, request); err != nil || got != want {
		t.Fatal("historical cancel result inferred from newer provider state", err, got)
	}
	var state string
	if err := pool.QueryRow(ctx, `SELECT state FROM identity.delivery_intents WHERE deployment='test' AND effect_id=$1`, b.RecordID).Scan(&state); err != nil || state != "confirmed" {
		t.Fatal("cancellation replay rewrote provider completion", err)
	}
}
