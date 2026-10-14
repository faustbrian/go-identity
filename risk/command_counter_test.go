package risk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCommandCounterPolicySeparatesProtectedAuthority(t *testing.T) {
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	scope := Context{Tenant: "tenant", Operation: "identity.password.change", Attempt: "attempt"}
	subject := Subject{User: "user", Session: "session", Network: "2001:db8::1"}
	command, err := policy.Prepare(scope, subject, now)
	if err != nil {
		t.Fatal("protected profile unavailable", err)
	}
	b := command.Bindings()
	if b.Phase != ReserveWithCommand || b.Window != 15*time.Minute || b.Limit != 5 || b.PreparedAt != now || len(b.Targets) != 4 {
		t.Fatal("wrong protected profile")
	}
	if err := policy.Validate(command, scope, subject, now); err != nil {
		t.Fatal("own protected command denied", err)
	}
	ephemeral := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("durable command reached ephemeral authority")
		return CounterResult{}, nil
	}))
	ephemeral.state.clock = func() time.Time {
		t.Fatal("foreign command reached clock")
		return now
	}
	if _, err := ephemeral.Mutate(context.Background(), command); err == nil {
		t.Fatal("ephemeral dispatch accepted protected command")
	}
	if _, err := ephemeral.Prepare(scope, subject, ReserveWithCommand); err == nil {
		t.Fatal("legacy ephemeral preparation widened")
	}
}

func TestCommandCounterPolicyClosedProfilesAndBounds(t *testing.T) {
	key, _ := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	p, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	scope := Context{Tenant: "tenant", Operation: "identity.admin.user-ban", Attempt: "attempt"}
	subject := Subject{Actor: "actor", Resource: "target", Network: "192.0.2.1"}
	command, err := p.Prepare(scope, subject, now)
	if err != nil || command.Bindings().Window != time.Hour || command.Bindings().Limit != 20 || p.Validate(command, scope, subject, now.Add(15*time.Minute-time.Microsecond)) != nil {
		t.Fatal("privileged profile not retained", err)
	}
	for _, at := range []time.Time{{}, now.Add(-time.Microsecond), now.Add(time.Nanosecond), now.Add(15 * time.Minute)} {
		if p.Validate(command, scope, subject, at) == nil {
			t.Fatal("invalid validation time admitted")
		}
	}
	for _, action := range []Action{"identity.password.signin", "identity.profile.get", "identity.health", "identity.risk.evaluate", "password.change", "IDENTITY.PASSWORD.CHANGE", "unknown"} {
		changed := scope
		changed.Operation = action
		if got, err := p.Prepare(changed, subject, now); err == nil || got.Bindings().Fingerprint != "" {
			t.Fatal("unprotected action admitted", action)
		}
	}
	for _, change := range []func(*Context, *Subject){
		func(c *Context, s *Subject) { c.Tenant = "" },
		func(c *Context, s *Subject) { c.Attempt = "" },
		func(c *Context, s *Subject) { s.Actor = "" },
		func(c *Context, s *Subject) { s.Resource = "" },
		func(c *Context, s *Subject) { s.Network = "::" },
		func(c *Context, s *Subject) { s.Network = "fe80::1%en0" },
		func(c *Context, s *Subject) { s.Network = strings.Repeat("a", 46) },
		func(c *Context, s *Subject) { s.Device = "extra" },
	} {
		c, s := scope, subject
		change(&c, &s)
		if got, err := p.Prepare(c, s, now); err == nil || got.Bindings().Fingerprint != "" {
			t.Fatal("invalid dimensions admitted")
		}
	}
	for _, at := range []time.Time{{}, now.Add(time.Nanosecond), now.In(time.FixedZone("other", 3600))} {
		if _, err := p.Prepare(scope, subject, at); err == nil {
			t.Fatal("invalid primary time admitted")
		}
	}
	config := testPolicyConfig()
	config.Profiles[2].Window, config.Profiles[2].Limit, config.Profiles[2].EvidenceTTL = time.Minute, 2, time.Second
	lower, _ := NewPolicy(config)
	lowerCounters, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: lower, Keys: []CounterDigestKey{key}})
	got, err := lowerCounters.Prepare(scope, subject, now)
	if err != nil || got.Bindings().Window != time.Minute || got.Bindings().Limit != 2 || lowerCounters.Validate(got, scope, subject, now.Add(time.Second)) == nil {
		t.Fatal("explicit lower bounds ignored", err)
	}
}

func TestCommandCounterPolicyScopeOwnershipRotationAndRedaction(t *testing.T) {
	key, _ := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	newer, _ := NewCounterDigestKey(8, bytes.Repeat([]byte{0x32}, 32))
	keys := []CounterDigestKey{newer, key}
	config := CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: keys}
	p, _ := NewCommandCounterPolicy(config)
	keys[0] = CounterDigestKey{}
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	scope := Context{Tenant: "tenant", Operation: "identity.password.change", Attempt: "attempt"}
	subject := Subject{User: "user", Session: "session", Network: "2001:db8::1"}
	command, err := p.Prepare(scope, subject, now)
	if err != nil {
		t.Fatal(err)
	}
	b := command.Bindings()
	if len(b.Targets[0].Keys) != 2 || b.Targets[0].Keys[0].Version != 8 {
		t.Fatal("caller key slice retained")
	}
	old, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: config.Policy, Keys: []CounterDigestKey{key}})
	oldCommand, _ := old.Prepare(scope, subject, now)
	for i, target := range b.Targets {
		if target.Keys[1] != oldCommand.Bindings().Targets[i].Keys[0] || !strings.HasPrefix(target.Keys[0].Encoded, "rc1:") {
			t.Fatal("rotation lost original alias")
		}
	}
	b.Targets[0].Keys[0].Encoded = "changed"
	b.Targets[0].Dimension = DeviceDimension
	if command.Bindings().Targets[0].Keys[0].Encoded == "changed" || command.Bindings().Targets[0].Dimension != TenantDimension {
		t.Fatal("storage projections alias state")
	}
	for _, change := range []func(*Context, *Subject){
		func(c *Context, s *Subject) { c.Tenant += "x" },
		func(c *Context, s *Subject) { c.Attempt += "x" },
		func(c *Context, s *Subject) { c.Operation = "identity.password.set" },
		func(c *Context, s *Subject) { s.User += "x" },
		func(c *Context, s *Subject) { s.Session += "x" },
		func(c *Context, s *Subject) { s.Network = "2001:db8::2" },
	} {
		c, s := scope, subject
		change(&c, &s)
		if p.Validate(command, c, s, now) == nil {
			t.Fatal("changed protected scope accepted")
		}
		changed, err := p.Prepare(c, s, now)
		if err != nil || changed.Bindings().Fingerprint == command.Bindings().Fingerprint {
			t.Fatal("scope not fingerprinted", err)
		}
	}
	canonical := subject
	canonical.Network = "2001:0db8:0:0:0:0:0:1"
	if p.Validate(command, scope, canonical, now) != nil {
		t.Fatal("canonical network equivalence lost")
	}
	other, _ := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: config.Policy, Keys: []CounterDigestKey{newer, key}})
	if other.Validate(command, scope, subject, now) == nil || p.Validate(CounterCommand{}, scope, subject, now) == nil {
		t.Fatal("foreign policy ownership admitted")
	}
	legacy := testCounterCoordinator(t, counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("unexpected IO")
		return CounterResult{}, nil
	}))
	ephemeral, _ := legacy.Prepare(testContext(), counterSubject(), BeforeCredential)
	if p.Validate(ephemeral, scope, subject, now) == nil {
		t.Fatal("ephemeral command accepted")
	}
	// Even a wrong internal owner assignment cannot convert the private lane.
	command.state.owner = legacy.state
	if _, err := legacy.Mutate(context.Background(), command); err == nil {
		t.Fatal("protected lane was erased by owner assignment")
	}
	command.state.owner = nil
	a, _ := config.Policy.Admit(scope.Operation)
	comparison, _ := prepareCounter(scope, subject, ReserveWithCommand, a, now, []CounterDigestKey{newer, key}, false)
	if comparison.Bindings().Fingerprint == command.Bindings().Fingerprint || comparison.Bindings().Targets[0].Keys[0] == command.Bindings().Targets[0].Keys[0] {
		t.Fatal("authority domains collide")
	}
	for _, value := range []any{config, p, command} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("sensitive serialization allowed")
		}
		if payload, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); err == nil || len(payload) != 0 {
			t.Fatal("sensitive text serialization allowed")
		}
		formatted := fmt.Sprintf("%+v", value)
		if strings.Contains(formatted, command.Bindings().Fingerprint) || strings.Contains(formatted, "tenant") {
			t.Fatal("diagnostic scope leak")
		}
	}
}

func TestCommandCounterPolicyInvalidSetup(t *testing.T) {
	key, _ := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	for _, config := range []CommandCounterPolicyConfig{
		{}, {Policy: testPolicy(t)}, {Keys: []CounterDigestKey{key}},
		{Policy: testPolicy(t), Keys: []CounterDigestKey{{}}},
		{Policy: testPolicy(t), Keys: []CounterDigestKey{key, key}},
		{Policy: testPolicy(t), Keys: []CounterDigestKey{key, key, key, key, key}},
	} {
		if p, err := NewCommandCounterPolicy(config); err == nil || p.state != nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	if _, err := (CommandCounterPolicy{}).Prepare(testContext(), counterSubject(), testContext().Now); err == nil {
		t.Fatal("zero policy admitted")
	}
}
