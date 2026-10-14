package risk

import (
	"context"
	"testing"
	"time"
)

func FuzzEvaluatorSourceBinding(f *testing.F) {
	f.Add("tenant", "attempt", "status", uint8(SignalClean), uint8(ServerVerified))
	f.Add("foreign", "attempt", "status", uint8(SignalClean), uint8(ServerVerified))
	policy, err := NewPolicy(testPolicyConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, tenant, attempt, name string, state, trust uint8) {
		status := cleanSource("status")
		status.Read = func(_ context.Context, c Context) (Signal, error) {
			s := testSignal(c, name, SignalState(state))
			s.Tenant, s.Attempt, s.Trust = tenant, attempt, SignalTrust(trust)
			return s, nil
		}
		e, err := NewEvaluator(EvaluatorConfig{Policy: policy, Clock: func() time.Time { return testContext().Now }, Timeout: time.Second, Sources: []Source{status, cleanSource("captcha")}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := e.Evaluate(context.Background(), EvaluateRequest{Context: testContext(), Phase: NonIssuing})
		if err == nil && got.Decision.Action == Allow && (tenant != "tenant" || attempt != "attempt" || name != "status" || state != uint8(SignalClean) || trust != uint8(ServerVerified)) {
			t.Fatal("foreign or untrusted source allowed")
		}
	})
}
