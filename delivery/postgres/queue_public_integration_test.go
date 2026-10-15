//go:build integration

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The concrete adapter implements the public Queue without consumer workflow glue.
func testFullPublicQueue(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner *EnqueueService, config EnqueueConfig, admission EnqueueCommandRequest, first delivery.EnqueueResult, querier *publicReconciliationQuerier, permit *bool) {
	t.Helper()
	workerScope := authorization.DecisionContext{PolicyRevision: 1, CorrelationID: "queue-worker", Request: authorization.Request{Tenant: authorization.TenantID(admission.Binding.TenantID), Action: "identity.delivery.process", Subject: authorization.Subject{ID: "queue-service", Kind: authorization.SubjectServiceAccount}, Resource: authorization.Resource{Type: "identity.delivery-worker", ID: "queue-worker"}}}
	queue, err := owner.NewQueue(WorkerConfig{Scope: workerScope, ProviderConfigVersion: 1})
	if err != nil {
		t.Fatal("owned full Queue construction", err)
	}
	var _ delivery.Queue = queue
	calls := 0
	sender := attemptTestSender(func(call context.Context, a delivery.Attempt) (delivery.DeliveryResult, error) {
		calls++
		if _, ok := call.Deadline(); !ok || a.Body != "Code: synthetic-code" || a.IdempotencyKey != string(a.IntentID) {
			t.Fatal("unbounded/unfrozen public send")
		}
		tx := beginIntentTestTransaction(t, call, pool)
		if _, err := tx.Exec(call, `SELECT effect_id FROM identity.delivery_intents FOR UPDATE NOWAIT`); err != nil {
			t.Fatal("send held SQL lock", err)
		}
		if err := tx.Rollback(call); err != nil {
			t.Fatal(err)
		}
		return delivery.DeliveryResult{State: delivery.StateAccepted, ObservedAt: time.Now().UTC()}, nil
	})
	service, err := delivery.New(config.Policies[1], queue, nil, sender)
	if err != nil {
		t.Fatal("full public composition", err)
	}
	changed := config.Policies[1]
	changed.SenderConcurrency++
	if _, err := delivery.New(changed, queue, nil, sender); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("divergent worker policy admitted", err)
	}
	request := delivery.EnqueueRequest{TenantID: delivery.TenantID(admission.Binding.TenantID), CommandID: admission.Binding.CommandID, Message: admission.Message, IdempotencyKey: admission.IdempotencyKey, Scope: &delivery.EnqueueScope{Binding: admission.Binding, ActorScope: admission.ActorScope, IdentifierID: admission.IdentifierID, ProviderConfigVersion: 1, ExpiresAt: admission.ExpiresAt}}
	*permit = false
	if _, err := service.Enqueue(ctx, request); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("denied bridge admission", err)
	}
	*permit = true
	if replay, err := service.Enqueue(ctx, request); err != nil || replay != first || calls != 0 {
		t.Fatal("bridge changed stable admission", err)
	}
	statusScope := admission.ActorScope.Clone()
	statusScope.Request.Action = "identity.delivery.status-get"
	statusRequest := delivery.StatusGetRequest{TenantID: request.TenantID, IntentID: first.IntentID, Scope: &delivery.StatusScope{UserID: admission.Binding.UserID, ActorScope: statusScope}}
	snapshot, err := service.StatusGet(ctx, statusRequest)
	if err != nil || snapshot.StatusVersion == 0 || snapshot.State != delivery.StateQueued {
		t.Fatal("bridge omitted atomic status fence", err)
	}
	mutation := func(op identity.FeatureOperation, actor string, kind authorization.SubjectKind, version uint64) *delivery.MutationScope {
		b := admission.Binding
		b.CommandID, _ = identity.NewCommandID()
		b.RecordID = string(first.IntentID)
		b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
		b.ActorID, b.ActorKind = identity.ActorID(actor), kind
		scope := admission.ActorScope.Clone()
		scope.Request.Action = authorization.Action(b.OperationID)
		scope.Request.Subject.ID, scope.Request.Subject.Kind = authorization.SubjectID(actor), kind
		return &delivery.MutationScope{Binding: b, ActorScope: scope, ExpectedStatusVersion: version}
	}
	cancel := delivery.CancelRequest{TenantID: request.TenantID, IntentID: first.IntentID, Reason: "workflow stopped", Scope: mutation(CancelOperation(), string(admission.Binding.ActorID), admission.Binding.ActorKind, snapshot.StatusVersion)}
	if result, err := service.Cancel(ctx, cancel); err != nil || !result.LocalCancelled {
		t.Fatal("bridge cancellation", err)
	}
	if result, err := service.Cancel(ctx, cancel); err != nil || !result.LocalCancelled {
		t.Fatal("bridge exact cancellation replay", err)
	}
	// A distinct intent exercises Service.ProcessOne and independently signed callbacks.
	request.CommandID, _ = identity.NewCommandID()
	scope := *request.Scope
	scope.Binding.CommandID = request.CommandID
	request.Scope = &scope
	request.IdempotencyKey = "public-queue-second"
	second, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := service.ProcessOne(ctx, delivery.ClaimRequest{TenantID: request.TenantID, WorkerID: "queue-worker"}); err != nil || !out.Claimed || calls != 1 {
		t.Fatal("public Service worker bridge", err)
	}
	statusRequest.IntentID = second.IntentID
	snapshot, err = service.StatusGet(ctx, statusRequest)
	if err != nil {
		t.Fatal(err)
	}
	first = second
	observed := time.Now().UTC().Truncate(time.Microsecond)
	body, _ := json.Marshal(map[string]any{"tenant_id": string(request.TenantID), "provider": "test-provider", "event_id": "public-queue-event", "intent_id": string(second.IntentID), "generation": 1, "status": uint8(delivery.StateDelivered), "observed_at": observed.Format(time.RFC3339Nano)})
	callback := delivery.SignedReceiptCallback{TenantID: request.TenantID, Provider: "test-provider", ProviderConfigVersion: 1, KeyID: "callback-key", SignedAt: time.Now().UTC(), Body: body}
	callback.Signature = receiptAuthOracle(t, "test", [32]byte{9}, receiptSignedInput{Tenant: string(callback.TenantID), Provider: callback.Provider, Version: callback.ProviderConfigVersion, KeyID: callback.KeyID, SignedAt: callback.SignedAt, Body: callback.Body})
	eventDigest := sha256.Sum256([]byte("public-queue-event"))
	receipt := delivery.ReceiptRecordRequest{TenantID: request.TenantID, Provider: "test-provider", ProviderEventID: "public-queue-event", IntentID: second.IntentID, Generation: 1, Status: delivery.StateDelivered, ObservedAt: observed, IdempotencyKey: hex.EncodeToString(eventDigest[:]), Scope: mutation(ReceiptOperation(), "provider-actor", authorization.SubjectServiceAccount, snapshot.StatusVersion), Callback: &callback}
	forged := receipt
	forged.Status = delivery.StateRejected
	if _, err := service.ReceiptRecord(ctx, forged); !errors.Is(err, delivery.ErrForbidden) {
		t.Fatal("normalized receipt substituted authenticated evidence", err)
	}
	if out, err := service.ReceiptRecord(ctx, receipt); err != nil || !out.Advanced || out.State != delivery.StateDelivered {
		t.Fatal("bridge signed receipt", err)
	}
	if out, err := service.ReceiptRecord(ctx, receipt); err != nil || !out.Advanced {
		t.Fatal("bridge receipt command replay", err)
	}
	// Raw Queue Claim/Complete and public reconciliation preserve the original key.
	request.CommandID, _ = identity.NewCommandID()
	scope = *request.Scope
	scope.Binding.CommandID = request.CommandID
	request.Scope = &scope
	request.IdempotencyKey = "public-queue-third"
	third, err := service.Enqueue(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := queue.Claim(ctx, delivery.ClaimRequest{TenantID: request.TenantID, WorkerID: "queue-worker"})
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != third.IntentID {
		t.Fatal("public Queue claim", err)
	}
	completion := delivery.CompleteRequest{TenantID: request.TenantID, IntentID: third.IntentID, Generation: claim.Attempt.Generation, WorkerID: "queue-worker", Invoked: true, Result: delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC()}}
	if _, err := queue.Complete(ctx, completion); err != nil {
		t.Fatal("public Queue completion", err)
	}
	statusRequest.IntentID = third.IntentID
	snapshot, err = service.StatusGet(ctx, statusRequest)
	if err != nil {
		t.Fatal(err)
	}
	first = third
	queryCalls := 0
	querier.call = func(work context.Context, q delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		queryCalls++
		if q.ProviderIdempotencyKey != string(third.IntentID) {
			t.Fatal("query invented provider key")
		}
		return delivery.OutcomeObservation{State: delivery.StateDelivered, ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}, nil
	}
	queryScope := &delivery.ReconcileScope{MutationScope: *mutation(ReconcileOperation(), "query-service", authorization.SubjectServiceAccount, snapshot.StatusVersion)}
	query := delivery.ReconcileRequest{TenantID: request.TenantID, IntentID: third.IntentID, Generation: claim.Attempt.Generation, IdempotencyKey: string(queryScope.Binding.CommandID), Scope: queryScope}
	if out, err := service.Reconcile(ctx, query); err != nil || out.State != delivery.StateDelivered || queryCalls != 1 {
		t.Fatal("public Queue reconciliation", err)
	}
	if _, err := service.Reconcile(ctx, query); err != nil || queryCalls != 1 {
		t.Fatal("query replay contacted provider", err)
	}
	if calls != 1 {
		t.Fatal("receipt/reconciliation resubmitted delivery")
	}
	request.CommandID, _ = identity.NewCommandID()
	scope = *request.Scope
	scope.Binding.CommandID = request.CommandID
	scope.ExpiresAt = time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	request.Scope = &scope
	request.IdempotencyKey = "public-queue-expired"
	if out, err := service.Enqueue(ctx, request); !errors.Is(err, delivery.ErrExpired) || out.State != delivery.CommitNotCommitted {
		t.Fatal("bridge lost known expired non-admission", err)
	}
}
