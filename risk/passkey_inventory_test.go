package risk

import (
	"context"
	"errors"
	"testing"
)

// The API's authenticated safe/read profile is not permission to enumerate a
// user's keys: the native inventory separately authenticates/authorizes self.
// This boundary proves the actual tenant/subject rate mutation and threshold.
func TestPasskeyInventoryUsesExistingSafeReadCounter(t *testing.T) {
	for _, count := range []uint64{1, 120, 121} {
		coordinator := testCounterCoordinator(t, counterStoreFunc(func(ctx context.Context, command CounterCommand) (CounterResult, error) {
			binding := command.Bindings()
			if binding.Operation != "identity.passkey.list" || binding.Phase != BeforeReturn || len(binding.Targets) != 2 {
				t.Fatal("inventory did not bind exact safe read")
			}
			return NewCounterResult(command, CounterCommitted, snapshotFor(command, count))
		}))
		scope := testContext()
		scope.Operation = "identity.passkey.list"
		command, err := coordinator.Prepare(scope, Subject{User: "user-a"}, BeforeReturn)
		if err != nil {
			t.Fatal("authenticated inventory rate profile unavailable", err)
		}
		result, err := coordinator.Mutate(context.Background(), command)
		want := SignalClean
		if count > 120 {
			want = SignalThrottle
		}
		if err != nil || result.Outcome != CounterCommitted || result.Signal.State != want {
			t.Fatal("inventory threshold did not preserve safe-read admission", err)
		}
		if _, err := coordinator.Prepare(scope, Subject{}, BeforeReturn); !errors.Is(err, ErrInvalidCounterCommand) {
			t.Fatal("missing subject created an inventory counter")
		}
	}
	if _, err := testPolicy(t).Admit("identity.passkey.list-all"); !errors.Is(err, ErrInvalidAction) {
		t.Fatal("unlisted inventory alias became enabled")
	}
}
