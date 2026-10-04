package postgres

import (
	"context"
	"fmt"
	"log/slog"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
)

// Queue is the owned full delivery adapter. It borrows EnqueueService's primary
// pool, policies, envelope and selected features; it owns no second coordinator,
// goroutine, sender or retry engine. Construction binds one worker/provider.
// Each command carries explicit authenticated workflow scope and original fences.
// Zero is invalid. Selected callbacks and policy must be concurrency-safe.
type Queue struct {
	owner  *EnqueueService
	worker *workerQueue
}

var _ delivery.BoundQueue = (*Queue)(nil)

// NewQueue selects full public composition without IO. Cancellation, signed
// receipts, reconciliation and StateTracking must already be selected and their
// migrations checked by NewEnqueueService. Legacy admission and NewWorker remain
// available without selecting this full profile. Worker scope is copied; current
// authorization is checked on every operation. Call delivery.New with the exact
// retained worker Config and a bounded Sender; no additional Renderer is needed.
func (s *EnqueueService) NewQueue(c WorkerConfig) (*Queue, error) {
	if s == nil || s.cancellation == nil || s.receipts == nil || s.reconciliation == nil {
		return nil, delivery.ErrInvalidInput
	}
	worker, err := s.newWorkerQueue(c)
	if err != nil {
		return nil, err
	}
	return &Queue{owner: s, worker: worker}, nil
}

func (*Queue) Backend() delivery.QueueBackend { return delivery.QueueBackendPostgreSQL }

// ValidateComposition rejects any drift from the retained worker retry, timeout,
// capacity, expiry and production profile before leasing or invoking a provider.
func (q *Queue) ValidateComposition(c delivery.Config) error {
	if q == nil || q.worker == nil || q.worker.store == nil || c.Validate() != nil {
		return delivery.ErrInvalidInput
	}
	if attemptPolicyDigest(c, q.worker.store.maximumDuration) != q.worker.store.policyDigest {
		return delivery.ErrConflict
	}
	return nil
}

func (q *Queue) Enqueue(ctx context.Context, r delivery.EnqueueRequest) (delivery.EnqueueResult, error) {
	if q == nil || q.owner == nil || r.Scope == nil || r.Scope.Binding.CommandID != r.CommandID || r.Scope.Binding.TenantID != identity.TenantID(r.TenantID) {
		return delivery.EnqueueResult{}, delivery.ErrInvalidInput
	}
	s := r.Scope
	return q.owner.Enqueue(ctx, EnqueueCommandRequest{Binding: s.Binding, ActorScope: s.ActorScope, IdentifierID: s.IdentifierID, ProviderConfigVersion: s.ProviderConfigVersion, ExpiresAt: s.ExpiresAt, Message: r.Message, IdempotencyKey: r.IdempotencyKey, NoOpEquivalent: r.NoOpEquivalent})
}

func (q *Queue) StatusGet(ctx context.Context, r delivery.StatusGetRequest) (delivery.StatusGetResult, error) {
	if q == nil || q.owner == nil || r.Scope == nil {
		return delivery.StatusGetResult{}, delivery.ErrInvalidInput
	}
	observed, err := q.owner.VersionedStatusGet(ctx, r, r.Scope.UserID, r.Scope.ActorScope)
	if err != nil {
		return delivery.StatusGetResult{}, err
	}
	observed.Status.StatusVersion = observed.StatusVersion
	return observed.Status, nil
}

func (q *Queue) Cancel(ctx context.Context, r delivery.CancelRequest) (delivery.CancelResult, error) {
	if q == nil || q.owner == nil || r.Scope == nil {
		return delivery.CancelResult{}, delivery.ErrInvalidInput
	}
	s := r.Scope
	r.Scope = nil
	return q.owner.Cancel(ctx, CancelCommandRequest{Binding: s.Binding, ActorScope: s.ActorScope, ExpectedStatusVersion: s.ExpectedStatusVersion, Request: r})
}

func (q *Queue) ReceiptRecord(ctx context.Context, r delivery.ReceiptRecordRequest) (delivery.ReceiptRecordResult, error) {
	if ctx == nil || q == nil || q.owner == nil || q.owner.receipts == nil || r.Scope == nil || r.Callback == nil {
		return delivery.ReceiptRecordResult{}, delivery.ErrInvalidInput
	}
	work, stop := context.WithTimeout(ctx, q.owner.executor.timeout)
	defer stop()
	callback := SignedReceiptCallback(*r.Callback)
	authenticated, _, err := q.owner.receipts.authenticate(work, callback)
	if err != nil {
		return delivery.ReceiptRecordResult{}, err
	}
	// The unsigned normalized projection cannot substitute any authenticated
	// field, including provider event identity and its deterministic dedupe key.
	if r.TenantID != authenticated.TenantID || r.Provider != authenticated.Provider || r.ProviderEventID != authenticated.ProviderEventID || r.IntentID != authenticated.IntentID || r.Generation != authenticated.Generation || r.Status != authenticated.Status || !r.ObservedAt.Equal(authenticated.ObservedAt) || r.IdempotencyKey != authenticated.IdempotencyKey {
		return delivery.ReceiptRecordResult{}, delivery.ErrForbidden
	}
	s := r.Scope
	return q.owner.RecordReceipt(work, ReceiptCommandRequest{Binding: s.Binding, ActorScope: s.ActorScope, ExpectedStatusVersion: s.ExpectedStatusVersion, Callback: callback})
}

func (q *Queue) Reconcile(ctx context.Context, r delivery.ReconcileRequest) (delivery.ReconcileResult, error) {
	if q == nil || q.owner == nil || r.Scope == nil || r.Scope.Binding.TenantID != identity.TenantID(r.TenantID) || r.Scope.Binding.RecordID != string(r.IntentID) || r.IdempotencyKey != string(r.Scope.Binding.CommandID) {
		return delivery.ReconcileResult{}, delivery.ErrInvalidInput
	}
	s := r.Scope
	return q.owner.Reconcile(ctx, ReconcileCommandRequest{Binding: s.Binding, ActorScope: s.ActorScope, ExpectedStatusVersion: s.ExpectedStatusVersion, ExpectedStep: s.ExpectedStep, Generation: r.Generation, Checkpoint: r.Checkpoint})
}

func (q *Queue) Claim(ctx context.Context, r delivery.ClaimRequest) (delivery.ClaimResult, error) {
	if q == nil || q.worker == nil {
		return delivery.ClaimResult{}, delivery.ErrInvalidInput
	}
	return q.worker.Claim(ctx, r)
}
func (q *Queue) Complete(ctx context.Context, r delivery.CompleteRequest) (delivery.CompleteResult, error) {
	if q == nil || q.worker == nil {
		return delivery.CompleteResult{}, delivery.ErrInvalidInput
	}
	return q.worker.Complete(ctx, r)
}
func (Queue) Format(s fmt.State, _ rune)   { redactWorker(s) }
func (Queue) LogValue() slog.Value         { return slog.StringValue("delivery.postgres.Queue(redacted)") }
func (Queue) MarshalJSON() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }
