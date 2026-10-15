//go:build integration

package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testReceiptAwareStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service, retired *EnqueueService, enqueue EnqueueCommandRequest, permit *bool) {
	t.Helper()
	enqueue.Binding.CommandID, _ = identity.NewCommandID()
	enqueue.ProviderConfigVersion, enqueue.IdempotencyKey = 2, "public-receipt-accepted-status"
	admitted, err := service.Enqueue(ctx, enqueue)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := service.policies.worker(2, service.executor.custody.store.codec)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: delivery.TenantID(enqueue.Binding.TenantID), WorkerID: "receipt-status-worker"})
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != admitted.IntentID {
		t.Fatal("status claim", err)
	}
	uncertain := delivery.CompleteRequest{TenantID: claim.Attempt.TenantID, IntentID: admitted.IntentID, WorkerID: "receipt-status-worker", Generation: claim.Attempt.Generation, Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC()}}
	original, err := worker.Complete(ctx, uncertain)
	if err != nil || original.State != delivery.StateOutcomeUnknown {
		t.Fatal("unknown worker outcome", err)
	}
	statusScope := enqueue.ActorScope.Clone()
	statusScope.Request.Action = "identity.delivery.status-get"
	target := delivery.StatusGetRequest{TenantID: claim.Attempt.TenantID, IntentID: admitted.IntentID}
	before, err := service.VersionedStatusGet(ctx, target, enqueue.Binding.UserID, statusScope)
	if err != nil || before.Status.State != delivery.StateOutcomeUnknown {
		t.Fatal("pre-receipt status", err)
	}
	binding := enqueue.Binding
	op := ReceiptOperation()
	binding.OperationID, binding.SchemaID, binding.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	binding.RecordID, binding.ActorID, binding.ActorKind = string(admitted.IntentID), "provider-actor", authorization.SubjectServiceAccount
	caller := enqueue.ActorScope.Clone()
	caller.Request.Action = authorization.Action(binding.OperationID)
	caller.Request.Subject.ID, caller.Request.Subject.Kind = authorization.SubjectID(binding.ActorID), binding.ActorKind
	request := ReceiptCommandRequest{ActorScope: caller, Callback: SignedReceiptCallback{TenantID: target.TenantID, Provider: "test-provider", ProviderConfigVersion: 2, KeyID: "callback-key"}}
	for index, state := range []delivery.DeliveryState{delivery.StateAccepted, delivery.StateBounced} {
		binding.CommandID, _ = identity.NewCommandID()
		request.Binding, request.ExpectedStatusVersion = binding, before.StatusVersion+uint64(index)
		event := "synthetic-status-accepted"
		if index == 1 {
			event = "synthetic-status-bounced"
		}
		observed := time.Now().UTC()
		request.Callback.SignedAt = observed
		request.Callback.Body, _ = json.Marshal(map[string]any{"tenant_id": string(target.TenantID), "provider": "test-provider", "event_id": event, "intent_id": string(target.IntentID), "generation": claim.Attempt.Generation, "status": uint8(state), "observed_at": observed.Format(time.RFC3339Nano)})
		request.Callback.Signature = receiptAuthOracle(t, "test", [32]byte{9}, receiptSignedInput{Tenant: string(target.TenantID), Provider: request.Callback.Provider, Version: 2, KeyID: request.Callback.KeyID, SignedAt: observed, Body: request.Callback.Body})
		if got, err := service.RecordReceipt(ctx, request); err != nil || got.State != state || !got.Advanced {
			t.Fatal("receipt status transition", err, got)
		}
		want := delivery.StatusGetResult{State: state, AttemptGeneration: claim.Attempt.Generation, Terminal: state == delivery.StateBounced}
		for _, reader := range []*EnqueueService{service, retired} {
			got, err := reader.StatusGet(ctx, target, binding.UserID, statusScope)
			if err != nil || got != want {
				t.Fatal("public status lost authenticated receipt", err, got)
			}
			snapshot, err := reader.VersionedStatusGet(ctx, target, binding.UserID, statusScope)
			if err != nil || snapshot.Status != want || snapshot.StatusVersion != request.ExpectedStatusVersion+1 {
				t.Fatal("versioned receipt status lost atomic fence", err, snapshot)
			}
		}
		if replay, err := worker.Complete(ctx, uncertain); err != nil || replay != original {
			t.Fatal("receipt rewrote original worker completion", err)
		}
		*permit = false
		if got, err := service.StatusGet(ctx, target, binding.UserID, statusScope); !errors.Is(err, delivery.ErrForbidden) || got != (delivery.StatusGetResult{}) {
			t.Fatal("receipt status bypassed current policy", err)
		}
		*permit = true
		if got, err := service.StatusGet(ctx, target, "foreign-user", statusScope); !errors.Is(err, delivery.ErrForbidden) || got != (delivery.StatusGetResult{}) {
			t.Fatal("receipt status disclosed foreign subject", err)
		}
	}
	if got, err := retired.RecordReceipt(ctx, request); !errors.Is(err, delivery.ErrInvalidInput) || got != (delivery.ReceiptRecordResult{}) {
		t.Fatal("metadata tracking enabled callback authority", err)
	}
	snapshot, err := retired.VersionedStatusGet(ctx, target, binding.UserID, statusScope)
	if err != nil {
		t.Fatal(err)
	}
	stopBinding := enqueue.Binding
	stopBinding.CommandID, _ = identity.NewCommandID()
	stopBinding.RecordID = string(target.IntentID)
	stopOp := CancelOperation()
	stopBinding.OperationID, stopBinding.SchemaID, stopBinding.SchemaVersion = stopOp.OperationID, stopOp.SchemaID, stopOp.SchemaVersion
	stopCaller := enqueue.ActorScope.Clone()
	stopCaller.Request.Action = authorization.Action(stopOp.OperationID)
	stop := CancelCommandRequest{Binding: stopBinding, ActorScope: stopCaller, ExpectedStatusVersion: snapshot.StatusVersion, Request: delivery.CancelRequest{TenantID: target.TenantID, IntentID: target.IntentID, ExpectedGeneration: claim.Attempt.Generation, Reason: "synthetic-terminal-stop"}}
	if got, err := retired.Cancel(ctx, stop); err != nil || got != (delivery.CancelResult{State: delivery.StateBounced}) {
		t.Fatal("cancellation lost receipt terminal outcome", err, got)
	}
	var preserved bool
	if err := pool.QueryRow(ctx, `SELECT h.outcome=$2 AND i.state='rejected' AND i.ciphertext IS NULL FROM identity.delivery_intents i JOIN identity.delivery_attempt_history h USING(deployment,tenant_id,effect_id) WHERE i.effect_id=$1`, string(admitted.IntentID), int16(delivery.StateOutcomeUnknown)).Scan(&preserved); err != nil || !preserved {
		t.Fatal("status fabricated a worker history rewrite", err)
	}
}
