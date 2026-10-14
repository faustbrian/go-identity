package risk

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestCounterConfigurationPinsEphemeralPolicyAndCompleteCustody(t *testing.T) {
	policy := testPolicy(t)
	newest, _ := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	older, _ := NewCounterDigestKey(6, bytes.Repeat([]byte{0x32}, 32))
	keys := []CounterDigestKey{newest, older}
	c, err := NewCounterCoordinator(CounterCoordinatorConfig{Policy: policy, Keys: keys, Clock: func() time.Time { return testContext().Now }, Timeout: time.Second, Store: counterStoreFunc(func(context.Context, CounterCommand) (CounterResult, error) {
		t.Fatal("dispatched store")
		return CounterResult{}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	command, err := c.Prepare(testContext(), counterSubject(), BeforeCredential)
	if err != nil {
		t.Fatal(err)
	}
	c.state.clock = func() time.Time { t.Fatal("sampled clock"); return time.Time{} }
	if command.ValidateConfiguration(policy, keys) != nil {
		t.Fatal("exact custody denied")
	}
	if newest.Version() != 7 || older.Version() != 6 || (CounterDigestKey{}).Version() != 0 {
		t.Fatal("incorrect version metadata")
	}
	for _, bad := range []Policy{{}, testPolicy(t)} {
		if command.ValidateConfiguration(bad, keys) == nil {
			t.Fatal("foreign policy identity admitted")
		}
	}
	foreign, _ := NewCounterDigestKey(7, bytes.Repeat([]byte{0x33}, 32))
	foreignOlder, _ := NewCounterDigestKey(6, bytes.Repeat([]byte{0x33}, 32))
	foreignVersion, _ := NewCounterDigestKey(8, bytes.Repeat([]byte{0x31}, 32))
	for _, bad := range [][]CounterDigestKey{nil, {}, {newest}, {older, newest}, {newest, newest}, {foreign, older}, {newest, foreignOlder}, {foreignVersion, older}, {newest, older, older}} {
		if command.ValidateConfiguration(policy, bad) == nil {
			t.Fatal("foreign or incomplete keys admitted")
		}
	}
	if (CounterCommand{}).ValidateConfiguration(policy, keys) == nil {
		t.Fatal("zero command admitted")
	}
	protected, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: keys})
	if err != nil {
		t.Fatal(err)
	}
	owned, err := protected.Prepare(Context{Tenant: "tenant", Operation: "identity.password.change", Attempt: "attempt"}, Subject{User: "user", Session: "session", Network: "2001:db8::1"}, testContext().Now.UTC().Truncate(time.Microsecond))
	if err != nil || owned.ValidateConfiguration(policy, keys) == nil {
		t.Fatal("protected lane admitted", err)
	}
	keys[0] = CounterDigestKey{}
	if command.ValidateConfiguration(policy, []CounterDigestKey{newest, older}) != nil {
		t.Fatal("caller slice retained")
	}
}
