package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// This adapter double proves core admission only, not durable persistence,
// authorization, CAS, encryption, provider authentication or interoperability.
type serviceQueue struct {
	enqueue   func(context.Context, EnqueueRequest) (EnqueueResult, error)
	backend   QueueBackend
	status    *StatusGetResult
	cancel    *CancelResult
	reconcile func(context.Context, ReconcileRequest) (ReconcileResult, error)
}

func (q *serviceQueue) Backend() QueueBackend { return q.backend }
func (q *serviceQueue) Enqueue(ctx context.Context, r EnqueueRequest) (EnqueueResult, error) {
	return q.enqueue(ctx, r)
}
func (*serviceQueue) Claim(context.Context, ClaimRequest) (ClaimResult, error) {
	return ClaimResult{}, nil
}
func (*serviceQueue) Complete(context.Context, CompleteRequest) (CompleteResult, error) {
	return CompleteResult{}, nil
}
func (q *serviceQueue) StatusGet(context.Context, StatusGetRequest) (StatusGetResult, error) {
	if q.status != nil {
		return *q.status, nil
	}
	return StatusGetResult{State: StateQueued}, nil
}
func (q *serviceQueue) Cancel(context.Context, CancelRequest) (CancelResult, error) {
	if q.cancel != nil {
		return *q.cancel, nil
	}
	return CancelResult{State: StateCancelled, LocalCancelled: true}, nil
}
func (*serviceQueue) ReceiptRecord(context.Context, ReceiptRecordRequest) (ReceiptRecordResult, error) {
	return ReceiptRecordResult{State: StateDelivered, Advanced: true}, nil
}
func (q *serviceQueue) Reconcile(ctx context.Context, r ReconcileRequest) (ReconcileResult, error) {
	if q.reconcile != nil {
		return q.reconcile(ctx, r)
	}
	return ReconcileResult{State: StateOutcomeUnknown}, nil
}

func admissionRequest() EnqueueRequest {
	return EnqueueRequest{TenantID: "tenant", Message: validMessage(), IdempotencyKey: "synthetic-dedupe-0001", CommandID: "AQEBAQEBAQEBAQEBAQEBAQ"}
}

func TestServiceRendersBeforeAdmissionAndFreezesMessage(t *testing.T) {
	r, err := NewTemplateRenderer([]Template{plainTemplate()})
	if err != nil {
		t.Fatal(err)
	}
	request := admissionRequest()
	var calls int
	q := &serviceQueue{enqueue: func(ctx context.Context, queued EnqueueRequest) (EnqueueResult, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Error("admission lacks deadline")
		}
		rendered, ok := queued.Rendered()
		if !ok || rendered.Body != "Hello synthetic-display" || rendered.Locale != "en" {
			t.Error("exact template not prepared")
		}
		queued.Message.Variables[0].TextValue = "adapter-local-mutation"
		queued.Message.LocaleChain[0] = "adapter-local-locale"
		return EnqueueResult{IntentID: "synthetic-intent-0001", Queued: true, State: CommitCommitted}, nil
	}}
	s, err := New(DefaultConfig(), q, r, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		t.Error("enqueue invoked sender")
		return DeliveryResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.Enqueue(context.Background(), request)
	if err != nil || result.State != CommitCommitted || !result.Queued || calls != 1 {
		t.Fatal("queue admission failed")
	}
	if request.Message.Variables[0].TextValue != "synthetic-display" || request.Message.LocaleChain[0] != "en-US" {
		t.Fatal("queue mutated caller message")
	}
	request.Message.TemplateVersion = 99
	if _, err := s.Enqueue(context.Background(), request); !errors.Is(err, ErrInvalidInput) || calls != 1 {
		t.Fatal("unsafe template reached queue")
	}
}

func TestServiceUnknownAdmissionPreservesCommandAndDoesNotRetry(t *testing.T) {
	r, _ := NewTemplateRenderer([]Template{plainTemplate()})
	var calls int
	q := &serviceQueue{enqueue: func(context.Context, EnqueueRequest) (EnqueueResult, error) {
		calls++
		return EnqueueResult{}, errors.New("synthetic-private-provider-detail")
	}}
	s, err := New(DefaultConfig(), q, r, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	request := admissionRequest()
	result, err := s.Enqueue(context.Background(), request)
	var unknown AdmissionUnknownError
	if !errors.Is(err, ErrOutcomeUnknown) || !errors.As(err, &unknown) || unknown.CommandID != request.CommandID || result.State != CommitUnknown || result.Queued || calls != 1 {
		t.Fatal("ambiguous admission lost recovery identity or retried")
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("adapter diagnostics leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Enqueue(ctx, request); !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatal("pre-admission cancellation reached adapter")
	}
	if _, err := s.Enqueue(nil, request); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("nil context admitted")
	}
}

func TestServiceProductionRejectsCaptureAndMissingComposition(t *testing.T) {
	r, _ := NewTemplateRenderer([]Template{plainTemplate()})
	c := DefaultConfig()
	c.Production = true
	q := &serviceQueue{}
	sender := senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil })
	if _, err := New(c, q, r, sender); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("undeclared durable backend admitted")
	}
	q.backend = QueueBackendPostgreSQL
	if _, err := New(c, q, r, captureCallback{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("capture sender in production")
	}
	if _, err := New(c, q, r, sender); err != nil {
		t.Fatal("explicit owned adapter profile rejected")
	}
	var nilQueue *serviceQueue
	for _, q := range []Queue{nil, nilQueue} {
		if _, err := New(c, q, r, sender); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("missing queue admitted")
		}
	}
	var nilRenderer *TemplateRenderer
	if _, err := New(c, q, nilRenderer, sender); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("typed-nil renderer admitted")
	}
}

func TestServiceNeverAttemptedTerminalStatusAndPendingCancellation(t *testing.T) {
	r, _ := NewTemplateRenderer([]Template{plainTemplate()})
	q := &serviceQueue{}
	s, err := New(DefaultConfig(), q, r, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []DeliveryState{StateCancelled, StateExpired, StateSuperseded} {
		q.status = &StatusGetResult{State: state, Terminal: true}
		out, err := s.StatusGet(context.Background(), StatusGetRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001"})
		if err != nil || out.State != state || out.AttemptGeneration != 0 {
			t.Error("never-attempted terminal intent lost durable status")
		}
	}
	q.cancel = &CancelResult{State: StateOutcomeUnknown, LocalCancelled: true}
	out, err := s.Cancel(context.Background(), CancelRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", ExpectedGeneration: 1, Reason: "workflow-cancel"})
	if err != nil || !out.LocalCancelled || out.RemoteCancellationConfirmed || out.State != StateOutcomeUnknown {
		t.Fatal("local prevention became remote cancellation proof or invalid outcome")
	}
}

func TestServiceOperationsRejectInvalidScopeAndGeneration(t *testing.T) {
	r, _ := NewTemplateRenderer([]Template{plainTemplate()})
	q := &serviceQueue{}
	s, _ := New(DefaultConfig(), q, r, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil }))
	if _, err := s.StatusGet(context.Background(), StatusGetRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("empty status scope")
	}
	if _, err := s.Cancel(context.Background(), CancelRequest{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("empty cancel scope")
	}
	if _, err := s.ReceiptRecord(context.Background(), ReceiptRecordRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Provider: "provider", ProviderEventID: "event", Status: StateDelivered, ObservedAt: time.Now().UTC(), IdempotencyKey: "synthetic-receipt-0001"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero receipt fence")
	}
	if _, err := s.Reconcile(context.Background(), ReconcileRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Checkpoint: "cursor", IdempotencyKey: "synthetic-reconcile-0001"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero reconcile fence")
	}
	status, err := s.StatusGet(context.Background(), StatusGetRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001"})
	if err != nil || status.State != StateQueued {
		t.Fatal("queued status")
	}
	receipt, err := s.ReceiptRecord(context.Background(), ReceiptRecordRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Provider: "provider", ProviderEventID: "event", Generation: 1, Status: StateDelivered, ObservedAt: time.Now().UTC(), IdempotencyKey: "synthetic-receipt-0001"})
	if err != nil || !receipt.Advanced || receipt.State != StateDelivered {
		t.Fatal("normalized receipt")
	}
	unknown, err := s.Reconcile(context.Background(), ReconcileRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Generation: 1, Checkpoint: "cursor", IdempotencyKey: "synthetic-reconcile-0001"})
	if err != nil || unknown.State != StateOutcomeUnknown || unknown.Retryable {
		t.Fatal("reconciliation resubmitted")
	}
	processed, err := s.ProcessOne(context.Background(), ClaimRequest{TenantID: "tenant", WorkerID: "worker"})
	if err != nil || processed.Claimed {
		t.Fatal("empty worker claim")
	}
}

func TestServiceReconcileStartsWithoutInventedProviderCursor(t *testing.T) {
	r, _ := NewTemplateRenderer([]Template{plainTemplate()})
	request := ReconcileRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Generation: 1, IdempotencyKey: "synthetic-reconcile-0001"}
	calls := 0
	q := &serviceQueue{reconcile: func(ctx context.Context, got ReconcileRequest) (ReconcileResult, error) {
		calls++
		if got != request {
			t.Fatal("reconciliation changed the initial snapshot")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded initial reconciliation")
		}
		return ReconcileResult{State: StateOutcomeUnknown}, nil
	}}
	s, _ := New(DefaultConfig(), q, r, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil }))
	out, err := s.Reconcile(context.Background(), request)
	if err != nil || calls != 1 || out.State != StateOutcomeUnknown || out.Retryable {
		t.Fatal("initial reconciliation denied or admitted resend", err)
	}
}

func TestServiceAdmissionShapeAndSensitiveDiagnostics(t *testing.T) {
	r, _ := NewTemplateRenderer([]Template{plainTemplate()})
	var calls int
	q := &serviceQueue{enqueue: func(context.Context, EnqueueRequest) (EnqueueResult, error) {
		calls++
		return EnqueueResult{IntentID: "synthetic-intent-0001", Queued: true, State: CommitCommitted}, nil
	}}
	s, _ := New(DefaultConfig(), q, r, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil }))
	for _, mutate := range []func(*EnqueueRequest){func(r *EnqueueRequest) { r.CommandID = "noncanonical" }, func(r *EnqueueRequest) { r.CommandID = "AAAAAAAAAAAAAAAAAAAAAA" }, func(r *EnqueueRequest) { r.IdempotencyKey = "short" }, func(r *EnqueueRequest) { r.TenantID = "" }} {
		request := admissionRequest()
		mutate(&request)
		if _, err := s.Enqueue(context.Background(), request); !errors.Is(err, ErrInvalidInput) || calls != 0 {
			t.Fatal("invalid command scope reached queue")
		}
	}
	request := admissionRequest()
	if _, ok := request.Rendered(); ok {
		t.Fatal("caller forged prepared rendering")
	}
	if strings.Contains(fmt.Sprintf("%#v", request), "example.invalid") {
		t.Fatal("admission diagnostics leaked")
	}
	if _, err := json.Marshal(request); !errors.Is(err, ErrSerializationForbidden) {
		t.Fatal("implicit plaintext queue persistence")
	}
}
