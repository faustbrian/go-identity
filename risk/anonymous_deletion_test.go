package risk

import (
	"bytes"
	"testing"
	"time"
)

func TestAnonymousSelfDeletionRequiresOriginalProtectedCounters(t *testing.T) {
	policy := testPolicy(t)
	key, err := NewCounterDigestKey(1, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	c := testContext()
	c.Operation = "identity.anonymous.delete"
	a, err := policy.Admit(c.Operation)
	if err != nil || a.Profile.Class != CredentialMutation || a.Profile.Phase != ReserveWithCommand {
		t.Fatal("anonymous deletion lacks protected admission", err)
	}
	s := Subject{User: "guest", Session: "original-guest-session", Network: "192.0.2.1"}
	command, err := counters.Prepare(c, s, c.Now)
	if err != nil || counters.Validate(command, c, s, c.Now) != nil {
		t.Fatal("missing atomic self-deletion counters", err)
	}
	for _, change := range []func(*Context, *Subject){func(c *Context, _ *Subject) { c.Tenant = "foreign" }, func(c *Context, _ *Subject) { c.Attempt = "foreign" }, func(_ *Context, s *Subject) { s.User = "permanent" }, func(_ *Context, s *Subject) { s.Session = "other" }, func(_ *Context, s *Subject) { s.Network = "192.0.2.2" }} {
		x, y := c, s
		change(&x, &y)
		if counters.Validate(command, x, y, c.Now) == nil {
			t.Fatal("deletion counter authority transferred")
		}
	}
	if counters.Validate(command, c, s, c.Now.Add(15*time.Minute)) == nil {
		t.Fatal("deletion counter expiry renewed")
	}
	for _, op := range []Action{"identity.anonymous.Delete", "identity.anonymous.delete ", "identity.anonymous.upgrade-prepare"} {
		c.Operation = op
		if _, err := counters.Prepare(c, s, c.Now); err == nil {
			t.Fatal("alias/unselected preparation admitted")
		}
	}
}
