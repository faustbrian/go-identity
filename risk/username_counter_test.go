package risk

import (
	"context"
	"testing"
)

func TestUsernameAvailabilityUsesBoundedNativeReadCounters(t *testing.T) {
	for _, test := range []struct {
		count uint64
		state SignalState
	}{{120, SignalClean}, {121, SignalThrottle}} {
		coordinator := testCounterCoordinator(t, counterStoreFunc(func(_ context.Context, c CounterCommand) (CounterResult, error) {
			return NewCounterResult(c, CounterCommitted, snapshotFor(c, test.count))
		}))
		scope := testContext()
		scope.Operation = "identity.username.available"
		command, err := coordinator.Prepare(scope, Subject{Network: "2001:db8::1"}, BeforeReturn)
		if err != nil {
			t.Fatal("availability lacks mandatory rate admission", err)
		}
		result, err := coordinator.Mutate(context.Background(), command)
		if err != nil || result.Outcome != CounterCommitted || result.Signal.State != test.state {
			t.Fatal("availability counter did not enforce the post-debit limit", err)
		}
		if _, err := coordinator.Prepare(scope, Subject{Network: "2001:db8::1", User: "arbitrary-subject"}, BeforeReturn); err == nil {
			t.Fatal("availability caller selected two identities for one counter")
		}
	}
}
