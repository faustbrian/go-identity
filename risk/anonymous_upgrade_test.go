package risk

import (
	"bytes"
	"testing"
	"time"
)

func TestAnonymousUpgradeRequiresOriginalProtectedCounters(t *testing.T) {
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
	c.Operation = "identity.anonymous.upgrade"
	admission, err := policy.Admit(c.Operation)
	if err != nil || admission.Profile.Class != CredentialMutation || admission.Profile.Phase != ReserveWithCommand {
		t.Fatal("upgrade must reserve protected credential-mutation counters", err)
	}
	source := Subject{User: "guest", Session: "guest-original-session", Network: "192.0.2.1"}
	plan, err := counters.Prepare(c, source, c.Now)
	if err != nil || counters.Validate(plan, c, source, c.Now) != nil {
		t.Fatal("original guest upgrade lacks bounded command counters", err)
	}
	for _, change := range []func(*Context, *Subject){
		func(c *Context, _ *Subject) { c.Operation = "identity.anonymous.delete" },
		func(c *Context, _ *Subject) { c.Tenant = "foreign" },
		func(c *Context, _ *Subject) { c.Attempt = "other-command" },
		func(_ *Context, s *Subject) { s.User = "permanent" },
		func(_ *Context, s *Subject) { s.Session = "other-session" },
		func(_ *Context, s *Subject) { s.Network = "192.0.2.2" },
	} {
		changed, subject := c, source
		change(&changed, &subject)
		if counters.Validate(plan, changed, subject, c.Now) == nil {
			t.Fatal("upgrade risk plan transferred to another command or source")
		}
	}
	if counters.Validate(plan, c, source, c.Now.Add(15*time.Minute)) == nil {
		t.Fatal("upgrade counter expiry was renewed")
	}
	for _, alias := range []Action{"identity.anonymous.Upgrade", "identity.anonymous.upgrade ", "identity.anonymous.upgrade-prepare"} {
		c.Operation = alias
		if _, err := counters.Prepare(c, source, c.Now); err == nil {
			t.Fatal("unselected upgrade alias admitted")
		}
	}
}
