package delivery_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

type outcomeQueryFunc func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error)

func (f outcomeQueryFunc) QueryOutcome(ctx context.Context, q delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
	return f(ctx, q)
}

func queryFixture() delivery.OutcomeQuery {
	return delivery.OutcomeQuery{TenantID: "tenant", IntentID: "synthetic-intent-0001", Generation: 3, ProviderIdempotencyKey: "synthetic-provider-key", Checkpoint: "synthetic-cursor"}
}

func TestOutcomeQueryReturnsOnlyAttributableBoundedEvidence(t *testing.T) {
	t.Parallel()
	q := queryFixture()
	for _, state := range []delivery.DeliveryState{delivery.StateAccepted, delivery.StateDelivered, delivery.StateRejected, delivery.StateBounced, delivery.StateCancelled, delivery.StateOutcomeUnknown, delivery.StateTransientFailure} {
		want := delivery.OutcomeObservation{State: state, ObservedAt: time.Now().UTC(), Checkpoint: "next-cursor"}
		calls := 0
		executor, err := delivery.NewOutcomeQueryExecutor(time.Second, 1, outcomeQueryFunc(func(ctx context.Context, got delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
			calls++
			if got != q {
				t.Fatal("provider query changed original fence or provider identity")
			}
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > time.Second {
				t.Fatal("provider query has no bounded deadline")
			}
			return want, nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		if got, err := executor.Query(context.Background(), q); err != nil || got != want || calls != 1 {
			t.Fatal("query lost provider evidence", err)
		}
	}
}

func TestOutcomeQueryFailuresCannotBecomeEvidence(t *testing.T) {
	t.Parallel()
	want := delivery.OutcomeObservation{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}
	for _, callback := range []outcomeQueryFunc{
		func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
			return want, errors.New("synthetic private provider diagnostics")
		},
		func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
			panic("synthetic private provider diagnostics")
		},
		func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
			return delivery.OutcomeObservation{State: delivery.StateQueued, ObservedAt: want.ObservedAt}, nil
		},
		func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
			return delivery.OutcomeObservation{State: delivery.StateDelivered, ObservedAt: want.ObservedAt, RetryAfter: time.Second}, nil
		},
		func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
			return delivery.OutcomeObservation{State: delivery.StateDelivered, ObservedAt: want.ObservedAt, Checkpoint: strings.Repeat("x", 513)}, nil
		},
	} {
		executor, err := delivery.NewOutcomeQueryExecutor(time.Second, 1, callback)
		if err != nil {
			t.Fatal(err)
		}
		got, err := executor.Query(context.Background(), queryFixture())
		if !errors.Is(err, delivery.ErrUnavailable) || got != (delivery.OutcomeObservation{}) || strings.Contains(err.Error(), "private") {
			t.Fatal("failed query fabricated provider evidence", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	executor, _ := delivery.NewOutcomeQueryExecutor(time.Second, 1, outcomeQueryFunc(func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		cancel()
		return want, nil
	}))
	if got, err := executor.Query(ctx, queryFixture()); !errors.Is(err, context.Canceled) || got != (delivery.OutcomeObservation{}) {
		t.Fatal("cancelled callback disclosed success", err)
	}
}

func TestOutcomeQueryInputAndSerializationBoundaries(t *testing.T) {
	t.Parallel()
	var nilCallback outcomeQueryFunc
	validCallback := outcomeQueryFunc(func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		return delivery.OutcomeObservation{}, nil
	})
	for _, input := range []struct {
		timeout     time.Duration
		concurrency uint8
		callback    delivery.OutcomeQuerier
	}{
		{0, 1, validCallback}, {time.Second, 0, validCallback}, {31 * time.Second, 1, validCallback}, {time.Second, 65, validCallback}, {time.Second, 1, nilCallback},
	} {
		if _, err := delivery.NewOutcomeQueryExecutor(input.timeout, input.concurrency, input.callback); !errors.Is(err, delivery.ErrInvalidInput) {
			t.Fatal("invalid query configuration", err)
		}
	}
	calls := 0
	executor, _ := delivery.NewOutcomeQueryExecutor(time.Second, 1, outcomeQueryFunc(func(context.Context, delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		calls++
		return delivery.OutcomeObservation{}, nil
	}))
	invalid := queryFixture()
	invalid.Generation = 0
	if _, err := executor.Query(context.Background(), invalid); !errors.Is(err, delivery.ErrInvalidInput) || calls != 0 {
		t.Fatal("invalid fence invoked provider", err)
	}
	if _, err := executor.Query(nil, queryFixture()); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("nil context", err)
	}
	var zero delivery.OutcomeQueryExecutor
	if _, err := zero.Query(context.Background(), queryFixture()); !errors.Is(err, delivery.ErrInvalidInput) {
		t.Fatal("zero executor", err)
	}
	for _, value := range []any{queryFixture(), delivery.OutcomeObservation{State: delivery.StateDelivered, ObservedAt: time.Now().UTC(), Checkpoint: "synthetic-private-cursor"}, executor} {
		if strings.Contains(fmt.Sprintf("%+v", value), "synthetic") {
			t.Fatal("query diagnostics leaked")
		}
		if _, err := json.Marshal(value); !errors.Is(err, delivery.ErrSerializationForbidden) {
			t.Fatal("implicit query persistence", err)
		}
	}
}

func TestOutcomeQueryCapacityCancellationAndReuse(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	query := outcomeQueryFunc(func(ctx context.Context, _ delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return delivery.OutcomeObservation{}, ctx.Err()
			}
		}
		return delivery.OutcomeObservation{State: delivery.StateOutcomeUnknown, ObservedAt: time.Now().UTC()}, nil
	})
	executor, err := delivery.NewOutcomeQueryExecutor(time.Second, 1, query)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := executor.Query(ctx, queryFixture()); done <- err }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		cancel()
		<-done
		t.Fatal("first query did not start")
	}
	blocked, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	got, blockedErr := executor.Query(blocked, queryFixture())
	stop()
	close(release)
	firstErr := <-done
	if !errors.Is(blockedErr, context.DeadlineExceeded) || got != (delivery.OutcomeObservation{}) || firstErr != nil || calls.Load() != 1 {
		t.Fatal("bounded slot wait invoked another provider query", blockedErr, firstErr)
	}
	if got, err := executor.Query(context.Background(), queryFixture()); err != nil || got.State != delivery.StateOutcomeUnknown || calls.Load() != 2 {
		t.Fatal("query slot not released", err)
	}
}

func TestOutcomeQueryLateSuccessIsNotEvidence(t *testing.T) {
	executor, err := delivery.NewOutcomeQueryExecutor(time.Second, 1, outcomeQueryFunc(func(ctx context.Context, _ delivery.OutcomeQuery) (delivery.OutcomeObservation, error) {
		<-ctx.Done()
		return delivery.OutcomeObservation{State: delivery.StateDelivered, ObservedAt: time.Now().UTC()}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if got, err := executor.Query(ctx, queryFixture()); !errors.Is(err, context.DeadlineExceeded) || got != (delivery.OutcomeObservation{}) {
		t.Fatal("late success became authoritative evidence", err)
	}
}
