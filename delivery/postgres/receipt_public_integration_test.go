//go:build integration

package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testAuthenticatedReceipts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, service *EnqueueService, enqueue EnqueueCommandRequest, permit *bool) {
	t.Helper()
	enqueue.Binding.CommandID, _ = identity.NewCommandID()
	enqueue.ProviderConfigVersion, enqueue.IdempotencyKey = 2, "public-receipt-submitted"
	admitted, err := service.Enqueue(ctx, enqueue)
	if err != nil {
		t.Fatal(err)
	}
	worker, err := service.policies.worker(2, service.executor.custody.store.codec)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := worker.Claim(ctx, delivery.ClaimRequest{TenantID: delivery.TenantID(enqueue.Binding.TenantID), WorkerID: "callback-worker"})
	if err != nil || !claim.Claimed || claim.Attempt.IntentID != admitted.IntentID {
		t.Fatal("callback worker claim", err)
	}
	b := enqueue.Binding
	b.CommandID, _ = identity.NewCommandID()
	b.RecordID, b.ActorID, b.ActorKind = string(admitted.IntentID), "provider-actor", authorization.SubjectServiceAccount
	op := ReceiptOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	scope := enqueue.ActorScope.Clone()
	scope.Request.Action = authorization.Action(b.OperationID)
	scope.Request.Subject.ID, scope.Request.Subject.Kind = authorization.SubjectID(b.ActorID), b.ActorKind
	statusScope := enqueue.ActorScope.Clone()
	statusScope.Request.Action = "identity.delivery.status-get"
	snapshot, err := service.VersionedStatusGet(ctx, delivery.StatusGetRequest{TenantID: claim.Attempt.TenantID, IntentID: admitted.IntentID}, b.UserID, statusScope)
	if err != nil {
		t.Fatal(err)
	}
	observed := time.Now().UTC().Truncate(time.Microsecond)
	wire := map[string]any{"tenant_id": string(b.TenantID), "provider": "test-provider", "event_id": "synthetic-public-event", "intent_id": b.RecordID, "generation": claim.Attempt.Generation, "status": uint8(delivery.StateDelivered), "observed_at": observed.Format(time.RFC3339Nano)}
	body, _ := json.Marshal(wire)
	callback := SignedReceiptCallback{TenantID: delivery.TenantID(b.TenantID), Provider: "test-provider", ProviderConfigVersion: 2, KeyID: "callback-key", SignedAt: time.Now().UTC(), Body: body}
	sign := func(q SignedReceiptCallback) SignedReceiptCallback {
		t.Helper()
		q.Signature = receiptAuthOracle(t, "test", [32]byte{9}, receiptSignedInput{Tenant: string(q.TenantID), Provider: q.Provider, Version: q.ProviderConfigVersion, KeyID: q.KeyID, SignedAt: q.SignedAt, Body: q.Body})
		return q
	}
	callback = sign(callback)
	request := ReceiptCommandRequest{Binding: b, ActorScope: scope, ExpectedStatusVersion: snapshot.StatusVersion, Callback: callback}
	commandCount := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity.commands WHERE purpose='identity.delivery.receipt-record'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	baseline := commandCount()
	*permit = false
	if got, err := service.RecordReceipt(ctx, request); !errors.Is(err, delivery.ErrForbidden) || got != (delivery.ReceiptRecordResult{}) {
		t.Fatal("denied callback disclosed effect", err)
	}
	*permit = true
	for index, mutate := range []func(*ReceiptCommandRequest){
		func(q *ReceiptCommandRequest) { q.Callback.Signature[0] ^= 1 },
		func(q *ReceiptCommandRequest) { q.Callback.ProviderConfigVersion = 1; q.Callback = sign(q.Callback) },
		func(q *ReceiptCommandRequest) {
			q.Binding.ActorID = "foreign"
			q.ActorScope.Request.Subject.ID = "foreign"
		},
		func(q *ReceiptCommandRequest) {
			q.Binding.ActorKind = authorization.SubjectUser
			q.ActorScope.Request.Subject.Kind = authorization.SubjectUser
		},
	} {
		altered := request
		altered.ActorScope = request.ActorScope.Clone()
		mutate(&altered)
		if got, err := service.RecordReceipt(ctx, altered); !errors.Is(err, delivery.ErrForbidden) || got != (delivery.ReceiptRecordResult{}) {
			t.Fatalf("forged callback scope mutation %d returned %v", index, err)
		}
	}
	if commandCount() != baseline {
		t.Fatal("unauthenticated callback reserved kernel command")
	}
	failed := request
	failed.Binding.CommandID, _ = identity.NewCommandID()
	if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages ADD CONSTRAINT callback_downstream_failure CHECK(topic<>'delivery.receipt-recorded.v1') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	if got, err := service.RecordReceipt(ctx, failed); err == nil || got != (delivery.ReceiptRecordResult{}) {
		t.Fatal("downstream callback failure fabricated success", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE outbox_messages DROP CONSTRAINT callback_downstream_failure`); err != nil {
		t.Fatal(err)
	}
	var restored bool
	if err := pool.QueryRow(ctx, `SELECT state='submitted' AND ciphertext IS NOT NULL AND status_version=$2::numeric AND NOT EXISTS(SELECT 1 FROM identity.delivery_receipts) FROM identity.delivery_intents WHERE effect_id=$1`, b.RecordID, strconv.FormatUint(snapshot.StatusVersion, 10)).Scan(&restored); err != nil || !restored {
		t.Fatal("failed callback retained effect prefix", err)
	}
	want := delivery.ReceiptRecordResult{Advanced: true, State: delivery.StateDelivered}
	if got, err := service.RecordReceipt(ctx, request); err != nil || got != want {
		t.Fatal("protected public callback commit", err, got)
	}
	// Envelopes can be freshly re-signed without changing the original command.
	request.Callback.SignedAt = time.Now().UTC()
	request.Callback = sign(request.Callback)
	if got, err := service.RecordReceipt(ctx, request); err != nil || got != want {
		t.Fatal("original callback replay lost immutable result", err, got)
	}
	var unchanged bool
	if err := pool.QueryRow(ctx, `SELECT status_version=$2::numeric AND ciphertext IS NULL AND (SELECT count(*) FROM identity.delivery_receipts)=1 AND (SELECT count(*) FROM identity.delivery_receipt_commands)=1 FROM identity.delivery_intents WHERE effect_id=$1`, b.RecordID, strconv.FormatUint(snapshot.StatusVersion+1, 10)).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("callback replay renewed fence or custody", err)
	}
	*permit = false
	if got, err := service.RecordReceipt(ctx, request); !errors.Is(err, delivery.ErrForbidden) || got != (delivery.ReceiptRecordResult{}) {
		t.Fatal("historical callback bypassed current policy", err)
	}
	*permit = true
	changed := request
	wire["status"] = uint8(delivery.StateRejected)
	changed.Callback.Body, _ = json.Marshal(wire)
	changed.Callback = sign(changed.Callback)
	if got, err := service.RecordReceipt(ctx, changed); !errors.Is(err, delivery.ErrConflict) || got != (delivery.ReceiptRecordResult{}) {
		t.Fatal("changed authenticated evidence reused command", err)
	}
	duplicate := request
	duplicate.Binding.CommandID, _ = identity.NewCommandID()
	duplicate.ExpectedStatusVersion++
	if got, err := service.RecordReceipt(ctx, duplicate); err != nil || got != (delivery.ReceiptRecordResult{State: delivery.StateDelivered, Deduplicated: true}) {
		t.Fatal("new-command event dedupe lost immutable result", err, got)
	}
	// The external policy changes only once the real protected result commits.
	// No timing hook, fake coordinator or in-memory commit marker substitutes
	// for authoritative persistence at this boundary.
	lateDenied := duplicate
	lateDenied.Binding.CommandID, _ = identity.NewCommandID()
	lateDenied.ExpectedStatusVersion++
	wire["status"], wire["event_id"] = uint8(delivery.StateDelivered), "synthetic-late-policy-event"
	lateDenied.Callback.Body, _ = json.Marshal(wire)
	lateDenied.Callback = sign(lateDenied.Callback)
	id, _ := base64.RawURLEncoding.DecodeString(string(lateDenied.Binding.CommandID))
	originalPolicy := service.executor.authorize
	service.executor.authorize = enqueueDecisionFunc(func(ctx context.Context, dc authorization.DecisionContext) (authorization.Decision, error) {
		var committed bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.delivery_receipt_commands WHERE command_id=$1)`, id).Scan(&committed); err != nil {
			return authorization.Decision{}, err
		}
		if committed {
			return authorization.Decision{Outcome: authorization.Deny, Revision: dc.PolicyRevision}, nil
		}
		return originalPolicy.Decide(ctx, dc)
	})
	if got, err := service.RecordReceipt(ctx, lateDenied); !errors.Is(err, delivery.ErrForbidden) || got != (delivery.ReceiptRecordResult{}) {
		t.Fatal("post-commit policy denial disclosed result", err)
	}
	service.executor.authorize = originalPolicy
	if got, err := service.RecordReceipt(ctx, lateDenied); err != nil || got != (delivery.ReceiptRecordResult{State: delivery.StateDelivered}) {
		t.Fatal("denied disclosure lost protected original command", err, got)
	}
}
