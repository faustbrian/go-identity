package valkey

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/risk"
)

func TestNativeDispatchConservesTruthAndNeverRetries(t *testing.T) {
	for _, tc := range []struct {
		name                                                   string
		transportError, malformed, cancelledAfter, unavailable bool
		outcome                                                risk.CounterOutcome
		wantError                                              error
	}{
		{"committed", false, false, false, false, risk.CounterCommitted, nil},
		{"lost_ack", true, false, false, false, risk.CounterUnknown, ErrOutcomeUnknown},
		{"partial", false, true, false, false, risk.CounterUnknown, ErrOutcomeUnknown},
		{"cancel_after_ack", false, false, true, false, risk.CounterCommitted, context.Canceled},
		{"unhealthy", false, false, false, true, risk.CounterNotCommitted, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, keys, _ := commandFixture(t, 9)
			layout, err := newCommandLayout("native-test", bytes.Repeat([]byte{1}, 32), p, keys)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			owner := mutationDispatcher{layout: layout, timeout: time.Second, execute: func(bounded context.Context, plan commandPlan) ([]string, error) {
				calls++
				if _, ok := bounded.Deadline(); !ok {
					t.Fatal("unbounded native dispatch")
				}
				if len(plan.keys) != 6 || plan.epoch == "" {
					t.Fatal("missing atomic selection")
				}
				if tc.transportError {
					return nil, errors.New("private upstream diagnostics")
				}
				if tc.malformed {
					return []string{"committed", plan.fingerprint}, nil
				}
				if tc.unavailable {
					return []string{"unavailable", plan.fingerprint}, nil
				}
				now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
				reply := []string{"committed", plan.fingerprint, strconv.FormatInt(now.UnixMicro(), 10)}
				for _, target := range plan.targets {
					reply = append(reply, string(target.Dimension), "1", strconv.FormatInt(now.UnixMicro(), 10), strconv.FormatInt(now.Add(plan.window).UnixMicro(), 10))
				}
				if tc.cancelledAfter {
					cancel()
				}
				return reply, nil
			}}
			c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: keys, Store: replyStoreFunc(func(ctx context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
				result, dispatchError := owner.mutate(ctx, command, [16]byte{1})
				if !errors.Is(dispatchError, tc.wantError) {
					t.Fatal("wrong dispatch error", dispatchError)
				}
				return result, dispatchError
			}), Clock: func() time.Time { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC) }, Timeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			command := prepareFixture(t, c, "tenant", "attempt", "192.0.2.1")
			got, err := c.Mutate(ctx, command)
			if err != nil || got.Outcome != tc.outcome || calls != 1 {
				t.Fatal("commit truth lost", err)
			}
			wantSignal := risk.SignalUnavailable
			if !tc.transportError && !tc.malformed && !tc.unavailable && !tc.cancelledAfter {
				wantSignal = risk.SignalClean
			}
			if got.Signal.State != wantSignal {
				t.Fatal("wrong admission signal")
			}
		})
	}
}

func TestNativeDispatchRejectsBeforeIO(t *testing.T) {
	p, keys, c := commandFixture(t, 9)
	layout, err := newCommandLayout("native-test", bytes.Repeat([]byte{1}, 32), p, keys)
	if err != nil {
		t.Fatal(err)
	}
	owner := mutationDispatcher{layout: layout, timeout: time.Second, execute: func(context.Context, commandPlan) ([]string, error) {
		t.Fatal("invalid dispatch performed IO")
		return nil, nil
	}}
	command := prepareFixture(t, c, "tenant", "attempt", "192.0.2.1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = owner.mutate(ctx, command, [16]byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel lost")
	}
	if _, err = owner.mutate(nil, command, [16]byte{1}); err == nil {
		t.Fatal("nil context admitted")
	}
	if _, err = owner.mutate(context.Background(), risk.CounterCommand{}, [16]byte{1}); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("zero command admitted")
	}
	if _, err = owner.mutate(context.Background(), command, [16]byte{}); !errors.Is(err, risk.ErrInvalidCounterCommand) {
		t.Fatal("zero epoch admitted")
	}
	var zero mutationDispatcher
	if _, err = zero.mutate(context.Background(), command, [16]byte{1}); err == nil {
		t.Fatal("zero dispatcher admitted")
	}
}

func TestNativeDispatchLateAcknowledgementRetainsCommitWithoutAdmission(t *testing.T) {
	p, keys, _ := commandFixture(t, 9)
	layout, err := newCommandLayout("native-test", bytes.Repeat([]byte{1}, 32), p, keys)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	calls := 0
	owner := mutationDispatcher{layout: layout, timeout: 100 * time.Millisecond, execute: func(ctx context.Context, plan commandPlan) ([]string, error) {
		calls++
		<-ctx.Done()
		reply := []string{"committed", plan.fingerprint, strconv.FormatInt(now.UnixMicro(), 10)}
		for _, target := range plan.targets {
			reply = append(reply, string(target.Dimension), "1", strconv.FormatInt(now.UnixMicro(), 10), strconv.FormatInt(now.Add(plan.window).UnixMicro(), 10))
		}
		return reply, nil
	}}
	c, err := risk.NewCounterCoordinator(risk.CounterCoordinatorConfig{Policy: p, Keys: keys, Store: replyStoreFunc(func(ctx context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
		return owner.mutate(ctx, command, [16]byte{1})
	}), Clock: func() time.Time { return now }, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	command := prepareFixture(t, c, "tenant", "attempt", "192.0.2.1")
	got, err := c.Mutate(ctx, command)
	if err != nil || got.Outcome != risk.CounterCommitted || calls != 1 || ctx.Err() != nil {
		t.Fatal("late acknowledgement lost commit truth", err)
	}
	if got.Signal.State != risk.SignalUnavailable {
		t.Fatal("late acknowledgement admitted after adapter deadline")
	}
}

func TestNativeDispatchKeepsEarlierDeadlineAndRedactsErrors(t *testing.T) {
	p, keys, c := commandFixture(t, 9)
	layout, err := newCommandLayout("native-test", bytes.Repeat([]byte{1}, 32), p, keys)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	owner := mutationDispatcher{layout: layout, timeout: time.Second, execute: func(bounded context.Context, _ commandPlan) ([]string, error) {
		got, ok := bounded.Deadline()
		if !ok || !got.Equal(deadline) {
			t.Fatal("caller deadline extended")
		}
		return nil, errors.New("private diagnostic")
	}}
	command := prepareFixture(t, c, "tenant", "attempt", "192.0.2.1")
	if _, err = owner.mutate(ctx, command, [16]byte{1}); err != ErrOutcomeUnknown || err.Error() != "risk/valkey: outcome unknown" {
		t.Fatal("upstream diagnostic leaked")
	}
	for _, timeout := range []time.Duration{0, 99 * time.Millisecond, 10*time.Second + time.Nanosecond} {
		invalid := owner
		invalid.timeout = timeout
		if _, err = invalid.mutate(ctx, command, [16]byte{1}); !errors.Is(err, risk.ErrInvalidPolicy) {
			t.Fatal("invalid bound admitted")
		}
	}
}
