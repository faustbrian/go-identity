package risk

import (
	"bytes"
	"context"
	"testing"
)

func TestStoredProviderRefreshRequiresItsOwnProtectedCounters(t *testing.T) {
	policy := testPolicy(t)
	scope := testContext()
	scope.Operation = "identity.account.refresh-token"
	subject := Subject{User: "account-owner", Session: "fresh-session", Network: "192.0.2.1"}
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	if assessment, err := policy.Assess(context.Background(), scope, nil); err != nil || assessment.Decision.Action != Deny {
		t.Fatal("refresh bypassed required risk signals", err)
	}
	clean := []Signal{testSignal(scope, "status", SignalClean), testSignal(scope, "captcha", SignalClean)}
	if assessment, err := policy.Assess(context.Background(), scope, clean); err != nil || assessment.Decision.Action != Allow {
		t.Fatal("clean refresh could not reach protected admission", err)
	}
	command, err := counters.Prepare(scope, subject, scope.Now)
	if err != nil || command.Bindings().Phase != ReserveWithCommand || len(command.Bindings().Targets) != 4 || counters.Validate(command, scope, subject, scope.Now) != nil {
		t.Fatal("refresh lacked original tenant, subject, session and network custody", err)
	}
	scope.Operation = "identity.account.link-token"
	if counters.Validate(command, scope, subject, scope.Now) == nil {
		t.Fatal("refresh counter custody admitted provider account linking")
	}
}
