package risk

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestOrganizationRoleBindingsRequireProtectedAdmission(t *testing.T) {
	policy := testPolicy(t)
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	scope := testContext()
	subject := Subject{Actor: "member", Resource: "organization-role", Network: "192.0.2.1"}
	for _, action := range []Action{"identity.organization.role.assign", "identity.organization.role.revoke", "identity.organization.role.create", "identity.organization.role.update", "identity.organization.role.delete"} {
		t.Run(string(action), func(t *testing.T) {
			scope := scope
			scope.Operation = action
			admitted, err := policy.Admit(action)
			if err != nil || admitted.Profile.Class != Privileged || admitted.Profile.Phase != ReserveWithCommand || admitted.Preflight != "" {
				t.Fatal("role management lacks protected admission", err)
			}
			denied, err := policy.Assess(context.Background(), scope, nil)
			if err != nil || denied.Decision.Action != Deny {
				t.Fatal("missing role-management signals did not deny", err)
			}
			allowed, err := policy.Assess(context.Background(), scope, []Signal{testSignal(scope, "status", SignalClean), testSignal(scope, "captcha", SignalClean)})
			if err != nil || allowed.Decision.Action != Allow {
				t.Fatal("verified role-management signals cannot proceed", err)
			}
			command, err := counters.Prepare(scope, subject, scope.Now)
			if err != nil || command.Bindings().Phase != ReserveWithCommand || len(command.Bindings().Targets) != 4 || counters.Validate(command, scope, subject, scope.Now) != nil {
				t.Fatal("role management cannot reserve exact protected counters", err)
			}
			foreign := subject
			foreign.Resource = "other-organization-role"
			if counters.Validate(command, scope, foreign, scope.Now) == nil {
				t.Fatal("role counter authority escaped its resource")
			}
			if counters.Validate(command, scope, subject, scope.Now.Add(15*time.Minute)) == nil {
				t.Fatal("role counter authority renewed its exclusive expiry")
			}
		})
	}
	for _, action := range []Action{"identity.organization.role.Assign", "identity.organization.role.assign ", "identity.organization.role.grant", "identity.organization.role.unknown"} {
		scope.Operation = action
		if _, err := counters.Prepare(scope, subject, scope.Now); err == nil {
			t.Fatal("unregistered role-management action admitted", action)
		}
	}
}
