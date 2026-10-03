package risk

import (
	"context"
	"testing"
)

func FuzzActionAdmission(f *testing.F) {
	f.Add("identity.password.signin")
	f.Add("identity.oauth-server.jwks")
	f.Add("identity.password.signin ")
	f.Add("")
	p, err := NewPolicy(testPolicyConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		admission, err := p.Admit(Action(raw))
		if err != nil {
			return
		}
		class, ok := canonicalOperations[Action(raw)]
		if !ok || admission.Operation != Action(raw) || admission.PolicyVersion != 3 {
			t.Fatal("noncanonical or unbound admission")
		}
		if class == DefaultDeny && admission.Preflight != Deny {
			t.Fatal("closed deny weakened")
		}
	})
}

func FuzzSignalIsolation(f *testing.F) {
	f.Add("tenant", "attempt", "status", uint8(SignalClean), uint8(ServerVerified))
	f.Add("foreign", "attempt", "status", uint8(SignalClean), uint8(ServerVerified))
	p, err := NewPolicy(testPolicyConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, tenant, attempt, name string, state, trust uint8) {
		c := testContext()
		s := testSignal(c, name, SignalState(state))
		s.Tenant, s.Attempt, s.Trust = tenant, attempt, SignalTrust(trust)
		got, err := p.Assess(context.Background(), c, []Signal{s, testSignal(c, "captcha", SignalClean)})
		if err != nil {
			return
		}
		if got.Decision.Action == Allow && (tenant != c.Tenant || attempt != c.Attempt || name != "status" || state != uint8(SignalClean) || trust != uint8(ServerVerified)) {
			t.Fatal("untrusted or foreign signal allowed")
		}
	})
}
