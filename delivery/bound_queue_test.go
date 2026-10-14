package delivery

import (
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// This double isolates core dispatch, not durable authorization or custody.
// The PostgreSQL public composition suite supplies the durable oracle.
type boundServiceQueue struct {
	*serviceQueue
	configurationError error
}

func (q *boundServiceQueue) ValidateComposition(Config) error { return q.configurationError }

func TestBoundAdmissionDelegatesBeforeRecipientRendering(t *testing.T) {
	request := admissionRequest()
	request.Message.Recipient = Recipient{}
	request.Scope = &EnqueueScope{Binding: identity.CommandBinding{CommandID: request.CommandID, TenantID: identity.TenantID(request.TenantID)}, IdentifierID: "AQEBAQEBAQEBAQEBAQEBAQ", ProviderConfigVersion: 1, ExpiresAt: time.Now().UTC()}
	q := &boundServiceQueue{serviceQueue: &serviceQueue{backend: QueueBackendPostgreSQL, enqueue: func(ctx context.Context, got EnqueueRequest) (EnqueueResult, error) {
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded owned admission")
		}
		if got.Message.Recipient != (Recipient{}) || got.Scope == nil || got.Scope.Binding.CommandID != request.CommandID {
			t.Fatal("core invented recipient or lost command")
		}
		if _, ok := got.Rendered(); ok {
			t.Fatal("core rendered before owned authorization")
		}
		return EnqueueResult{IntentID: "synthetic-intent-0001", Queued: true, State: CommitCommitted}, nil
	}}}
	service, err := New(DefaultConfig(), q, nil, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		t.Fatal("admission invoked Sender")
		return DeliveryResult{}, nil
	}))
	if err != nil {
		t.Fatal("owned composition still requires a redundant renderer", err)
	}
	if out, err := service.Enqueue(context.Background(), request); err != nil || !out.Queued {
		t.Fatal("recipient-free owned admission rejected", err)
	}
	q.configurationError = ErrConflict
	if _, err := New(DefaultConfig(), q, nil, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil })); !errors.Is(err, ErrConflict) {
		t.Fatal("processing policy mismatch admitted", err)
	}
}

func TestBoundAdmissionPreservesOriginalUnknownCommand(t *testing.T) {
	request := admissionRequest()
	request.Message.Recipient = Recipient{}
	request.Scope = &EnqueueScope{Binding: identity.CommandBinding{CommandID: request.CommandID, TenantID: identity.TenantID(request.TenantID)}}
	original := CommandID("AgICAgICAgICAgICAgICAg")
	q := &boundServiceQueue{serviceQueue: &serviceQueue{backend: QueueBackendPostgreSQL, enqueue: func(context.Context, EnqueueRequest) (EnqueueResult, error) {
		return EnqueueResult{}, AdmissionUnknownError{CommandID: original}
	}}}
	s, err := New(DefaultConfig(), q, nil, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Enqueue(context.Background(), request)
	var unknown AdmissionUnknownError
	if !errors.As(err, &unknown) || unknown.CommandID != original {
		t.Fatal("lost original recovery identity")
	}
	q.enqueue = func(context.Context, EnqueueRequest) (EnqueueResult, error) {
		return EnqueueResult{}, ErrOutcomeUnknown
	}
	_, err = s.Enqueue(context.Background(), request)
	if !errors.Is(err, ErrOutcomeUnknown) || errors.As(err, &unknown) {
		t.Fatal("invented recovery command when original is unknown")
	}
	q.enqueue = func(context.Context, EnqueueRequest) (EnqueueResult, error) {
		return EnqueueResult{State: CommitInProgress}, nil
	}
	_, err = s.Enqueue(context.Background(), request)
	if !errors.Is(err, ErrOutcomeUnknown) || errors.As(err, &unknown) {
		t.Fatal("invented recovery command from an in-progress result")
	}
}

func TestBoundAdmissionRejectsRecipientAndMismatchedScope(t *testing.T) {
	request := admissionRequest()
	request.Scope = &EnqueueScope{Binding: identity.CommandBinding{CommandID: request.CommandID, TenantID: identity.TenantID(request.TenantID)}}
	q := &boundServiceQueue{serviceQueue: &serviceQueue{backend: QueueBackendPostgreSQL, enqueue: func(context.Context, EnqueueRequest) (EnqueueResult, error) {
		t.Fatal("invalid scope reached adapter")
		return EnqueueResult{}, nil
	}}}
	s, err := New(DefaultConfig(), q, nil, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*EnqueueRequest){
		func(*EnqueueRequest) {},
		func(r *EnqueueRequest) { r.Message.Recipient = Recipient{}; r.Scope = nil },
		func(r *EnqueueRequest) {
			r.Message.Recipient = Recipient{}
			scope := *r.Scope
			scope.Binding.TenantID = "foreign"
			r.Scope = &scope
		},
		func(r *EnqueueRequest) {
			r.Message.Recipient = Recipient{}
			scope := *r.Scope
			scope.Binding.CommandID = "foreign"
			r.Scope = &scope
		},
	} {
		r := request
		mutate(&r)
		if _, err := s.Enqueue(context.Background(), r); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("unsafe admission accepted", err)
		}
	}
}

func TestServiceRejectsScopeDowngradeAndMissingStatusFence(t *testing.T) {
	q := &serviceQueue{backend: QueueBackendCapture}
	renderer, err := NewTemplateRenderer([]Template{plainTemplate()})
	if err != nil {
		t.Fatal(err)
	}
	sender := senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil })
	legacy, err := New(DefaultConfig(), q, renderer, sender)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.StatusGet(context.Background(), StatusGetRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Scope: &StatusScope{}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("legacy queue silently discarded authenticated status scope", err)
	}
	if _, err := legacy.Cancel(context.Background(), CancelRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Reason: "stop", Scope: &MutationScope{}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("legacy queue silently discarded mutation scope", err)
	}
	if _, err := legacy.Reconcile(context.Background(), ReconcileRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Generation: 1, IdempotencyKey: "synthetic-key-0001", Scope: &ReconcileScope{}}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("legacy queue silently discarded query scope", err)
	}
	bound, err := New(DefaultConfig(), &boundServiceQueue{serviceQueue: &serviceQueue{backend: QueueBackendPostgreSQL}}, nil, sender)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bound.StatusGet(context.Background(), StatusGetRequest{TenantID: "tenant", IntentID: "synthetic-intent-0001", Scope: &StatusScope{}}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("bound queue exposed a fabricated zero status fence", err)
	}
}

func TestBoundRequestPublicValidationAndKnownExpiry(t *testing.T) {
	request := admissionRequest()
	request.Message.Recipient = Recipient{}
	request.Scope = &EnqueueScope{Binding: identity.CommandBinding{CommandID: request.CommandID, TenantID: identity.TenantID(request.TenantID)}}
	if err := request.Validate(); err != nil {
		t.Error("valid recipient-free request rejected by public validator", err)
	}
	q := &boundServiceQueue{serviceQueue: &serviceQueue{backend: QueueBackendPostgreSQL, enqueue: func(context.Context, EnqueueRequest) (EnqueueResult, error) {
		return EnqueueResult{State: CommitNotCommitted}, ErrExpired
	}}}
	s, err := New(DefaultConfig(), q, nil, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) { return DeliveryResult{}, nil }))
	if err != nil {
		t.Fatal(err)
	}
	if out, err := s.Enqueue(context.Background(), request); !errors.Is(err, ErrExpired) || out.State != CommitNotCommitted {
		t.Fatal("known expired non-admission became ambiguous", err)
	}
}
