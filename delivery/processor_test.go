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

// This queue double proves the core handshake only, never database durability.
type processingQueue struct {
	claim    func(context.Context, ClaimRequest) (ClaimResult, error)
	complete func(context.Context, CompleteRequest) (CompleteResult, error)
}

func (q *processingQueue) Claim(ctx context.Context, r ClaimRequest) (ClaimResult, error) {
	return q.claim(ctx, r)
}
func (q *processingQueue) Complete(ctx context.Context, r CompleteRequest) (CompleteResult, error) {
	return q.complete(ctx, r)
}

func TestProcessorRecordsClaimBeforeSendAndCompletesExactFence(t *testing.T) {
	a := testAttempt()
	request := ClaimRequest{TenantID: a.TenantID, WorkerID: "worker-1"}
	claimed, sent, completed := false, false, false
	q := &processingQueue{
		claim: func(ctx context.Context, r ClaimRequest) (ClaimResult, error) {
			if r != request {
				t.Fatal("claim scope changed")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("claim IO unbounded")
			}
			claimed = true
			return ClaimResult{Claimed: true, Attempt: a, LeaseUntil: time.Now().UTC().Add(time.Minute)}, nil
		},
		complete: func(ctx context.Context, r CompleteRequest) (CompleteResult, error) {
			if !sent || r.TenantID != a.TenantID || r.IntentID != a.IntentID || r.Generation != a.Generation || r.WorkerID != request.WorkerID || !r.Invoked || r.Result.State != StateAccepted {
				t.Fatal("completion lost exact attempt fence/evidence")
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("completion IO unbounded")
			}
			completed = true
			return CompleteResult{State: StateAccepted, Commit: CommitCommitted}, nil
		},
	}
	p, err := newAttemptProcessor(DefaultConfig(), q, senderFunc(func(ctx context.Context, _ Attempt) (DeliveryResult, error) {
		if !claimed || completed {
			t.Fatal("sender ran before durable claim or after completion")
		}
		sent = true
		return DeliveryResult{State: StateAccepted, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.processOne(context.Background(), request)
	if err != nil || !completed || !out.Claimed || out.IntentID != a.IntentID || out.Completion.State != StateAccepted {
		t.Fatal("claim-send-complete failed")
	}
}

func TestProcessorCancellationStillCheckpointsUnknownWithoutRetry(t *testing.T) {
	a := testAttempt()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls, completions := 0, 0
	q := &processingQueue{claim: func(context.Context, ClaimRequest) (ClaimResult, error) {
		return ClaimResult{Claimed: true, Attempt: a, LeaseUntil: time.Now().UTC().Add(time.Minute)}, nil
	},
		complete: func(ctx context.Context, r CompleteRequest) (CompleteResult, error) {
			completions++
			if ctx.Err() != nil || !r.Invoked || r.Result.State != StateOutcomeUnknown {
				t.Fatal("cancelled sender skipped bounded unknown bookkeeping")
			}
			return CompleteResult{State: StateOutcomeUnknown, Commit: CommitCommitted}, nil
		}}
	p, err := newAttemptProcessor(DefaultConfig(), q, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		calls++
		cancel()
		return DeliveryResult{}, errors.New("synthetic-private-provider-error")
	}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.processOne(ctx, ClaimRequest{TenantID: a.TenantID, WorkerID: "worker"})
	if !errors.Is(err, ErrOutcomeUnknown) || calls != 1 || completions != 1 || out.IntentID != a.IntentID || out.Completion.Commit != CommitCommitted {
		t.Fatal("ambiguous call lost recovery or retried")
	}
}

func TestProcessorCompletionFailureRetainsStableRecovery(t *testing.T) {
	for _, completion := range []func(context.Context, CompleteRequest) (CompleteResult, error){
		func(context.Context, CompleteRequest) (CompleteResult, error) {
			return CompleteResult{}, errors.New("synthetic-private-queue-error")
		},
		func(context.Context, CompleteRequest) (CompleteResult, error) { return CompleteResult{}, nil },
		func(context.Context, CompleteRequest) (CompleteResult, error) {
			return CompleteResult{State: StateOutcomeUnknown, Commit: CommitUnknown}, nil
		},
	} {
		a := testAttempt()
		calls := 0
		q := &processingQueue{claim: func(context.Context, ClaimRequest) (ClaimResult, error) {
			return ClaimResult{Claimed: true, Attempt: a, LeaseUntil: time.Now().UTC().Add(time.Minute)}, nil
		}, complete: completion}
		p, err := newAttemptProcessor(DefaultConfig(), q, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
			calls++
			return DeliveryResult{State: StateDelivered, ObservedAt: time.Now().UTC()}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		out, err := p.processOne(context.Background(), ClaimRequest{TenantID: a.TenantID, WorkerID: "worker"})
		var recovery OutcomeUnknownError
		if !errors.As(err, &recovery) || recovery.IntentID != a.IntentID || out.Completion.Commit != CommitUnknown || calls != 1 || strings.Contains(fmt.Sprint(err), "private") {
			t.Fatal("completion failure invented delivery/rejection or lost recovery")
		}
	}
}

func TestProcessorNeverSendsCrossTenantOrMalformedClaims(t *testing.T) {
	for _, change := range []func(*ClaimResult){
		func(c *ClaimResult) { c.Attempt.TenantID = "other-tenant" },
		func(c *ClaimResult) { c.Attempt.Generation = 0 },
		func(c *ClaimResult) { c.LeaseUntil = time.Time{} },
		func(c *ClaimResult) { c.Claimed = false },
	} {
		a := testAttempt()
		claim := ClaimResult{Claimed: true, Attempt: a, LeaseUntil: time.Now().UTC().Add(time.Minute)}
		change(&claim)
		q := &processingQueue{claim: func(context.Context, ClaimRequest) (ClaimResult, error) { return claim, nil }, complete: func(context.Context, CompleteRequest) (CompleteResult, error) {
			t.Fatal("malformed scope completed")
			return CompleteResult{}, nil
		}}
		p, err := newAttemptProcessor(DefaultConfig(), q, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
			t.Fatal("invalid claim sent")
			return DeliveryResult{}, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = p.processOne(context.Background(), ClaimRequest{TenantID: a.TenantID, WorkerID: "worker"}); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("malformed claim admitted")
		}
	}
}

func TestProcessorNoWorkAndPreCancelledNeverInvokeSender(t *testing.T) {
	claims := 0
	q := &processingQueue{claim: func(context.Context, ClaimRequest) (ClaimResult, error) { claims++; return ClaimResult{}, nil }, complete: func(context.Context, CompleteRequest) (CompleteResult, error) {
		t.Fatal("empty work completed")
		return CompleteResult{}, nil
	}}
	p, err := newAttemptProcessor(DefaultConfig(), q, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		t.Fatal("empty work sent")
		return DeliveryResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := ClaimRequest{TenantID: "tenant", WorkerID: "worker"}
	if out, err := p.processOne(context.Background(), request); err != nil || out.Claimed {
		t.Fatal("empty queue not handled")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.processOne(ctx, request); !errors.Is(err, context.Canceled) || claims != 1 {
		t.Fatal("pre-cancelled process claimed work")
	}
	var nilQueue *processingQueue
	if _, err := newAttemptProcessor(DefaultConfig(), nilQueue, senderFunc(nil)); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("typed nil dependencies admitted")
	}
}

func TestProcessorCancelledAfterClaimReportsNoInvocation(t *testing.T) {
	a := testAttempt()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := &processingQueue{claim: func(context.Context, ClaimRequest) (ClaimResult, error) {
		cancel()
		return ClaimResult{Claimed: true, Attempt: a, LeaseUntil: time.Now().UTC().Add(time.Minute)}, nil
	},
		complete: func(ctx context.Context, r CompleteRequest) (CompleteResult, error) {
			if ctx.Err() != nil || r.Invoked || r.Result != (DeliveryResult{}) {
				t.Fatal("no-invocation evidence lost")
			}
			return CompleteResult{State: StateCancelled, Commit: CommitCommitted}, nil
		}}
	p, err := newAttemptProcessor(DefaultConfig(), q, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		t.Fatal("cancelled-before-send called provider")
		return DeliveryResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.processOne(ctx, ClaimRequest{TenantID: a.TenantID, WorkerID: "worker"})
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrOutcomeUnknown) || out.Completion.State != StateCancelled {
		t.Fatal("known unsent cancellation misclassified as ambiguous")
	}
}

func TestProcessorCapacityWaitDoesNotLeaseMoreWork(t *testing.T) {
	c := DefaultConfig()
	c.SenderConcurrency = 1
	q := &processingQueue{claim: func(context.Context, ClaimRequest) (ClaimResult, error) {
		t.Fatal("capacity wait leased work")
		return ClaimResult{}, nil
	}}
	p, err := newAttemptProcessor(c, q, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		t.Fatal("capacity wait sent")
		return DeliveryResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	p.slots <- struct{}{}
	defer func() { <-p.slots }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := p.processOne(ctx, ClaimRequest{TenantID: "tenant", WorkerID: "worker"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("capacity wait ignored cancellation")
	}
}

func TestProcessorTransferPrivacyAndShape(t *testing.T) {
	a := testAttempt()
	claim := ClaimResult{Claimed: true, Attempt: a, LeaseUntil: time.Now().UTC().Add(time.Minute)}
	complete := CompleteRequest{TenantID: a.TenantID, IntentID: a.IntentID, WorkerID: "worker", Generation: 1, Invoked: true, Result: DeliveryResult{State: StateAccepted, ProviderReference: "synthetic-private-reference", ObservedAt: time.Now().UTC()}}
	for _, value := range []any{claim, &claim, complete, &complete} {
		if strings.Contains(fmt.Sprintf("%+v", value), "synthetic") {
			t.Fatal("queue transfer diagnostics leaked")
		}
		if data, err := json.Marshal(value); len(data) != 0 || !errors.Is(err, ErrSerializationForbidden) {
			t.Fatal("queue transfer serialized")
		}
	}
	if complete.Validate() != nil {
		t.Fatal("valid invocation rejected")
	}
	complete.Invoked = false
	if !errors.Is(complete.Validate(), ErrInvalidInput) {
		t.Fatal("contradictory invocation accepted")
	}
	complete.Result = DeliveryResult{}
	if complete.Validate() != nil {
		t.Fatal("valid non-invocation rejected")
	}
	complete.Generation = 0
	if !errors.Is(complete.Validate(), ErrInvalidInput) {
		t.Fatal("zero generation accepted")
	}
}

func TestProcessorPreservesQueueAmbiguityAndGenerationConflict(t *testing.T) {
	a := testAttempt()
	q := &processingQueue{claim: func(context.Context, ClaimRequest) (ClaimResult, error) {
		return ClaimResult{}, fmt.Errorf("synthetic-private-queue: %w", ErrOutcomeUnknown)
	}}
	p, err := newAttemptProcessor(DefaultConfig(), q, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		t.Fatal("ambiguous claim sent")
		return DeliveryResult{}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := ClaimRequest{TenantID: a.TenantID, WorkerID: "worker"}
	if _, err := p.processOne(context.Background(), request); !errors.Is(err, ErrOutcomeUnknown) || strings.Contains(fmt.Sprint(err), "private") {
		t.Fatal("claim ambiguity misclassified or diagnostics leaked")
	}
	q.claim = func(context.Context, ClaimRequest) (ClaimResult, error) {
		return ClaimResult{Claimed: true, Attempt: a, LeaseUntil: time.Now().UTC().Add(time.Minute)}, nil
	}
	q.complete = func(context.Context, CompleteRequest) (CompleteResult, error) { return CompleteResult{}, ErrConflict }
	p, err = newAttemptProcessor(DefaultConfig(), q, senderFunc(func(context.Context, Attempt) (DeliveryResult, error) {
		return DeliveryResult{State: StateAccepted, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.processOne(context.Background(), request)
	if !errors.Is(err, ErrConflict) || !errors.Is(err, ErrOutcomeUnknown) || out.Completion.Commit != CommitConflict {
		t.Fatal("fenced completion lost conflict or external uncertainty")
	}
}
