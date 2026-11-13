package reference

import (
	"context"
	"testing"

	"github.com/faustbrian/go-identity/risk"
	migrations "github.com/faustbrian/go-migrations/v3"
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

func TestOAuthReadinessRequiresSelectedSuccessorWithoutChangingHistoricalGuards(t *testing.T) {
	_, _, features := serverFixture(t)
	state := features.state
	history := migrationHistory{namespace: "native-session-fixture", owners: map[migrations.Version]ModuleID{1: "identity/session/postgres"}, guards: []migrationGuard{{version: 1, schema: "session_store", constraints: []string{"session_issuances.session_issuances_purpose_v3", "sessions.session_record_binding_v7"}}}}
	state.features.socialOAuth = &socialOAuthState{signin: &socialSigninState{sessionSchema: "session_store"}}
	actual := readinessCatalogGuards(state, history)
	if len(actual) != 1 || actual[0].constraints[0] != "session_issuances.session_issuances_purpose_oauth_v1" || actual[0].constraints[1] != "sessions.session_record_binding_v7" {
		t.Fatal("readiness required a removed predecessor or changed another owner's guard")
	}
	if history.guards[0].constraints[0] != "session_issuances.session_issuances_purpose_v3" {
		t.Fatal("readiness rewrote immutable collision/history inputs")
	}
	state.features.socialOAuth = nil
	if got := readinessCatalogGuards(state, history); got[0].constraints[0] != history.guards[0].constraints[0] {
		t.Fatal("unselected OAuth changed readiness")
	}
}
