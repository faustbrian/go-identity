package risk

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestDomainEvidenceRequiresProtectedScopedAdmission(t *testing.T) {
	policy := testPolicy(t)
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Actor: "organization-admin", Resource: "organization", Network: "192.0.2.1"}
	for _, action := range []Action{"identity.organization.domain.evidence.apply", "identity.organization.domain.evidence.revoke"} {
		t.Run(string(action), func(t *testing.T) {
			c := testContext()
			c.Operation = action
			a, err := policy.Admit(action)
			if err != nil || a.Profile.Class != Privileged || a.Profile.Phase != ReserveWithCommand || a.Preflight != "" {
				t.Fatal("domain evidence missing protected admission", err)
			}
			for _, signals := range [][]Signal{nil, {testSignal(c, "status", SignalClean)}, {testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalUnavailable)}} {
				got, err := policy.Assess(context.Background(), c, signals)
				if err != nil || got.Decision.Action != Deny {
					t.Fatal("missing/unavailable original domain evidence signal admitted", err)
				}
			}
			got, err := policy.Assess(context.Background(), c, []Signal{testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean)})
			if err != nil || got.Decision.Action != Allow {
				t.Fatal("valid protected observations denied", err)
			}
			command, err := counters.Prepare(c, subject, c.Now)
			if err != nil || command.Bindings().Phase != ReserveWithCommand || len(command.Bindings().Targets) != 4 || counters.Validate(command, c, subject, c.Now) != nil {
				t.Fatal("missing transaction-owned evidence counters", err)
			}
			for _, change := range []func(*Context, *Subject){
				func(c *Context, _ *Subject) { c.Tenant = "foreign" },
				func(c *Context, _ *Subject) { c.Attempt = "foreign" },
				func(c *Context, _ *Subject) { c.Operation = "identity.organization.domain.reserve" },
				func(_ *Context, s *Subject) { s.Actor = "other-admin" },
				func(_ *Context, s *Subject) { s.Resource = "other-organization" },
				func(_ *Context, s *Subject) { s.Network = "192.0.2.2" },
			} {
				x, y := c, subject
				change(&x, &y)
				if counters.Validate(command, x, y, c.Now) == nil {
					t.Fatal("domain evidence counter authority transferred")
				}
			}
			if counters.Validate(command, c, subject, c.Now.Add(15*time.Minute)) == nil {
				t.Fatal("original evidence expiry renewed")
			}
		})
	}
	for _, action := range []Action{"identity.organization.domain.evidence.Apply", "identity.organization.domain.evidence.apply ", "identity.organization.domain.evidence.verify", "identity.sso.domain-verify", "identity.sso.domain-challenge"} {
		c := testContext()
		c.Operation = action
		if _, err := counters.Prepare(c, subject, c.Now); err == nil {
			t.Fatal("alias or unfinished SSO action admitted")
		}
	}
}
