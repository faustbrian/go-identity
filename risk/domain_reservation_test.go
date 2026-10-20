package risk

import (
	"bytes"
	"context"
	"testing"
)

func TestDomainReservationUsesProtectedNonTransferableAdmission(t *testing.T) {
	policy := testPolicy(t)
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Actor: "actor", Resource: "organization", Network: "192.0.2.1"}
	for _, action := range []Action{"identity.organization.domain.reserve", "identity.organization.domain.withdraw"} {
		t.Run(string(action), func(t *testing.T) {
			c := testContext()
			c.Operation = action
			for _, signals := range [][]Signal{nil, {testSignal(c, "status", SignalClean)}, {testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalUnavailable)}} {
				assessment, err := policy.Assess(context.Background(), c, signals)
				if err != nil || assessment.Decision.Action != Deny {
					t.Fatal("domain mutation bypassed current risk signals", err)
				}
			}
			assessment, err := policy.Assess(context.Background(), c, []Signal{testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean)})
			if err != nil || assessment.Decision.Action != Allow {
				t.Fatal("admitted domain mutation cannot reach protected reservation", err)
			}
			command, err := counters.Prepare(c, subject, c.Now)
			if err != nil || command.Bindings().Phase != ReserveWithCommand || len(command.Bindings().Targets) != 4 || counters.Validate(command, c, subject, c.Now) != nil {
				t.Fatal("domain mutation lacks exact transaction-owned risk counters", err)
			}
			for _, change := range []func(*Context, *Subject){
				func(c *Context, _ *Subject) { c.Tenant = "foreign-tenant" },
				func(c *Context, _ *Subject) { c.Attempt = "foreign-attempt" },
				func(c *Context, _ *Subject) {
					if action == "identity.organization.domain.reserve" {
						c.Operation = "identity.organization.domain.withdraw"
					} else {
						c.Operation = "identity.organization.domain.reserve"
					}
				},
				func(_ *Context, s *Subject) { s.Actor = "foreign-actor" },
				func(_ *Context, s *Subject) { s.Resource = "foreign-organization" },
				func(_ *Context, s *Subject) { s.Network = "192.0.2.2" },
			} {
				changed, target := c, subject
				change(&changed, &target)
				if counters.Validate(command, changed, target, c.Now) == nil {
					t.Fatal("domain risk reservation transferred scope")
				}
			}
			for _, alias := range []Action{"identity.organization.domain.get", "identity.organization.domain.verify", "identity.organization.domain.Reserve", "identity.organization.domain.withdraw "} {
				c.Operation = alias
				if _, err := counters.Prepare(c, subject, c.Now); err == nil {
					t.Fatal("unselected domain alias acquired mutation authority")
				}
			}
		})
	}
}
