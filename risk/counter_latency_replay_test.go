package risk

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCounterReplayWithNativeLatencyCannotRenewOriginalExpiry(t *testing.T) {
	now := testContext().Now
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var original CounterResult
	coordinator, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}, Timeout: time.Second, Clock: func() time.Time { return now }, Store: counterStoreFunc(func(_ context.Context, command CounterCommand) (CounterResult, error) {
		if original.state == nil {
			// TIME belongs to the actual native effect after the request began.
			// The retained authoritative snapshot is identical on every replay.
			now = now.Add(100 * time.Millisecond)
			snapshot := snapshotFor(command, 1)
			for i := range snapshot {
				snapshot[i].ObservedAt = now
				snapshot[i].WindowStartedAt = now
				snapshot[i].WindowExpiresAt = now.Add(command.Bindings().Window)
			}
			original, err = NewCounterResult(command, CounterCommitted, snapshot)
		}
		return original, err
	})})
	if err != nil {
		t.Fatal(err)
	}
	first, err := coordinator.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := coordinator.Mutate(context.Background(), first)
	if err != nil || initial.Signal.State != SignalClean {
		t.Fatal("initial delayed native observation unavailable", err)
	}
	now = now.Add(time.Second)
	reprepared, err := coordinator.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []CounterCommand{first, reprepared} {
		replayed, err := coordinator.Mutate(context.Background(), command)
		if err != nil || replayed.Outcome != CounterCommitted || replayed.Signal.State != SignalClean || !initial.Signal.ObservedAt.Equal(replayed.Signal.ObservedAt) || !initial.Signal.ExpiresAt.Equal(replayed.Signal.ExpiresAt) {
			t.Fatal("native latency let replay renew original counter expiry", err)
		}
	}
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		now = initial.Signal.ExpiresAt.Add(offset)
		command, err := coordinator.Prepare(testContext(), counterSubject(), BeforeCredential)
		if err != nil {
			t.Fatal(err)
		}
		result, err := coordinator.Mutate(context.Background(), command)
		if err != nil || result.Outcome != CounterCommitted {
			t.Fatal("expiry lost original commit", err)
		}
		if offset < 0 {
			if result.Signal.State != SignalClean || !result.Signal.ExpiresAt.Equal(initial.Signal.ExpiresAt) {
				t.Fatal("original exclusive horizon changed")
			}
		} else if result.Signal.State != SignalUnavailable || !result.Signal.ObservedAt.IsZero() || !result.Signal.ExpiresAt.IsZero() || result.Signal.RetryAfter != 0 {
			t.Fatal("expired original snapshot retained positive facts")
		}
	}
}
