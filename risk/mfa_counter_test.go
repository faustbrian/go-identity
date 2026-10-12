package risk

import (
	"bytes"
	"testing"
	"time"
)

func TestMFACompletionCountersRetainProtectedPolicyWithoutSession(t *testing.T) {
	key, _ := NewCounterDigestKey(1, bytes.Repeat([]byte{71}, 32))
	policy, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: testPolicy(t), Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	now := testContext().Now.UTC().Truncate(time.Microsecond)
	scope := Context{Tenant: "tenant", Operation: "identity.mfa.totp-verify", Attempt: "attempt"}
	subject := Subject{User: "original-subject", Network: "127.0.0.1"}
	command, err := policy.PrepareMFACompletion(scope, subject, "original-child", now)
	if err != nil {
		t.Fatal("anonymous MFA counter unavailable", err)
	}
	b := command.Bindings()
	if b.Limit != 5 || b.Window != 15*time.Minute || b.Phase != ReserveWithCommand || len(b.Targets) != 4 || b.Targets[2].Dimension != CapabilityDimension {
		t.Fatal("MFA weakened protected limits")
	}
	if policy.ValidateMFACompletion(command, scope, subject, "original-child", now) != nil {
		t.Fatal("original MFA intent rejected")
	}
	if policy.ValidateVerification(command, scope, subject, "original-child", now) == nil || policy.Validate(command, scope, subject, now) == nil {
		t.Fatal("MFA crossed another counter lane")
	}
	changed := scope
	changed.Operation = "identity.mfa.enable"
	if _, err := policy.PrepareMFACompletion(changed, subject, "original-child", now); err == nil {
		t.Fatal("MFA enrollment silently became sessionless")
	}
	if policy.ValidateMFACompletion(command, scope, subject, "other-child", now) == nil || policy.ValidateMFACompletion(command, scope, subject, "original-child", now.Add(15*time.Minute)) == nil {
		t.Fatal("changed or expired child adopted intent")
	}
	subject.Session = "invented-session"
	if _, err := policy.PrepareMFACompletion(scope, subject, "original-child", now); err == nil {
		t.Fatal("fabricated session admitted")
	}
}
