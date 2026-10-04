package delivery_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

func TestCompletionPolicyPublicAdapterConsumption(t *testing.T) {
	t.Parallel()
	config := delivery.DefaultConfig()
	config.BackoffCeilings = []time.Duration{0, time.Nanosecond, time.Nanosecond, time.Nanosecond, time.Nanosecond}
	policy, err := delivery.NewCompletionPolicy(config)
	if err != nil {
		t.Fatal(err)
	}
	// The constructor must freeze policy, not retain a caller-owned backing array.
	config.BackoffCeilings[1] = time.Minute
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	snapshot := delivery.CompletionSnapshot{State: delivery.StateAttempting, Generation: 7, ExpectedGeneration: 7, AttemptNumber: 1, Now: now, ValidUntil: now.Add(time.Hour)}
	evidence := delivery.DeliveryResult{State: delivery.StateTransientFailure, ObservedAt: now}
	for range 100 {
		decision, err := policy.Decide(context.Background(), snapshot, evidence)
		if err != nil || decision.State != delivery.StateRetryWait || decision.ErasePayload || decision.NextAttemptAt.Before(now) || decision.NextAttemptAt.After(now.Add(time.Nanosecond)) {
			t.Fatal("public policy changed frozen retry bounds")
		}
	}
	snapshot.ExpectedGeneration = 8
	if _, err := policy.Decide(context.Background(), snapshot, evidence); !errors.Is(err, delivery.ErrConflict) {
		t.Fatal("adapter policy admitted stale generation")
	}
}

func TestCompletionPolicyRequiresConstructionAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	if _, err := delivery.NewCompletionPolicy(delivery.Config{}); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("zero config constructed policy")
	}
	var zero delivery.CompletionPolicy
	if _, err := zero.Decide(context.Background(), delivery.CompletionSnapshot{}, delivery.DeliveryResult{}); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("zero policy usable")
	}
	policy, err := delivery.NewCompletionPolicy(delivery.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if decision, err := policy.Decide(ctx, delivery.CompletionSnapshot{}, delivery.DeliveryResult{}); !errors.Is(err, context.Canceled) || decision != (delivery.CompletionDecision{}) {
		t.Fatal("cancelled policy returned a usable decision")
	}
	if _, err := policy.Decide(nil, delivery.CompletionSnapshot{}, delivery.DeliveryResult{}); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("nil context usable")
	}
}

func TestCompletionPolicyPreservesUnknownAndExpiredCustody(t *testing.T) {
	t.Parallel()
	policy, err := delivery.NewCompletionPolicy(delivery.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	snapshot := delivery.CompletionSnapshot{State: delivery.StateAttempting, Generation: 1, ExpectedGeneration: 1, AttemptNumber: 5, CancelRequested: true, Now: now, ValidUntil: now}
	decision, err := policy.Decide(context.Background(), snapshot, delivery.DeliveryResult{State: delivery.StateOutcomeUnknown, ObservedAt: now})
	if err != nil || decision.State != delivery.StateOutcomeUnknown || !decision.ErasePayload || !decision.NextAttemptAt.IsZero() {
		t.Fatal("expiry/cancellation fabricated external outcome")
	}
}

func ExampleCompletionPolicy_Decide() {
	policy, err := delivery.NewCompletionPolicy(delivery.DefaultConfig())
	if err != nil {
		panic(err)
	}
	// Synthetic current database-time view for this example. Real adapters read
	// authoritative state and apply all decision components under generation CAS.
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	current := delivery.CompletionSnapshot{State: delivery.StateAttempting, Generation: 1, ExpectedGeneration: 1, AttemptNumber: 1, Now: now, ValidUntil: now.Add(time.Minute)}
	decision, err := policy.Decide(context.Background(), current, delivery.DeliveryResult{State: delivery.StateDelivered, ObservedAt: now})
	if err != nil {
		panic(err)
	}
	fmt.Println(decision.State == delivery.StateDelivered, decision.ErasePayload)
	// Output: true true
}
