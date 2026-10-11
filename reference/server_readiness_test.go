package reference

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/risk"
)

// These cases prove early denial without crossing any external boundary.
// Positive readiness is exercised only by the native integration fixture.
func TestReferenceServerReadinessRequiresCurrentPublishedCustody(t *testing.T) {
	for _, name := range []string{"nil-server", "nil-context", "canceled", "closed", "uninitialized", "initializing", "empty", "missing-counter", "missing-health", "missing-check", "busy"} {
		t.Run(name, func(t *testing.T) {
			_, _, features := serverFixture(t)
			state := features.state
			state.features.ready = true
			tenant := state.tenants["tenant"]
			tenant.counter = routedCounterStore(func(context.Context, risk.CounterCommand) (risk.CounterResult, error) {
				panic("readiness debited counter")
			})
			tenant.health = &velocityHealth{check: func(context.Context) error { panic("early denial crossed native health") }}
			server := &Server{state: state}
			ctx := t.Context()
			switch name {
			case "nil-server":
				server = nil
			case "nil-context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				state.closed = true
			case "uninitialized":
				state.features.ready = false
			case "initializing":
				state.features.initializing = true
			case "empty":
				state.tenants = nil
			case "missing-counter":
				tenant.counter = nil
			case "missing-health":
				tenant.health = nil
			case "missing-check":
				tenant.health = &velocityHealth{}
			case "busy":
				tenant.busy = true
			}
			observation := server.Readiness(ctx)
			if observation.Ready || len(observation.Failures) != 1 || state.active != 0 {
				t.Fatal("early denial admitted or retained work")
			}
		})
	}
}
