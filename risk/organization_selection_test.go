package risk

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestOrganizationSelectionRequiresExactProtectedAdmission(t *testing.T) {
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
	scope.Operation = "identity.organization.active-set"
	subject := Subject{Actor: "member", Resource: "exact-session", Network: "192.0.2.1"}
	for _, signals := range [][]Signal{
		nil,
		{testSignal(scope, "status", SignalClean)},
		{testSignal(scope, "status", SignalClean), testSignal(scope, "captcha", SignalUnavailable)},
	} {
		assessment, err := policy.Assess(context.Background(), scope, signals)
		if err != nil || assessment.Decision.Action != Deny {
			t.Fatal("selection bypassed mandatory current signals", err)
		}
	}
	assessment, err := policy.Assess(context.Background(), scope, []Signal{testSignal(scope, "status", SignalClean), testSignal(scope, "captcha", SignalClean)})
	if err != nil || assessment.Decision.Action != Allow {
		t.Fatal("clean selection cannot reach protected reservation", err)
	}
	command, err := counters.Prepare(scope, subject, scope.Now)
	if err != nil || command.Bindings().Phase != ReserveWithCommand || len(command.Bindings().Targets) != 4 || counters.Validate(command, scope, subject, scope.Now) != nil {
		t.Fatal("selection cannot reserve exact protected counters", err)
	}
	for _, change := range []func(*Context, *Subject){
		func(c *Context, _ *Subject) { c.Tenant = "foreign-tenant" },
		func(c *Context, _ *Subject) { c.Attempt = "foreign-attempt" },
		func(c *Context, _ *Subject) { c.Operation = "identity.organization.create" },
		func(_ *Context, s *Subject) { s.Actor = "foreign-member" },
		func(_ *Context, s *Subject) { s.Resource = "sibling-session" },
		func(_ *Context, s *Subject) { s.Network = "192.0.2.2" },
	} {
		changed, target := scope, subject
		change(&changed, &target)
		if counters.Validate(command, changed, target, scope.Now) == nil {
			t.Fatal("selection counter reservation transferred scope")
		}
	}
	if counters.Validate(command, scope, subject, scope.Now.Add(15*time.Minute)) == nil {
		t.Fatal("selection counter reservation renewed its exclusive expiry")
	}
	for _, action := range []Action{"identity.organization.active-get", "identity.organization.team.active-set", "identity.organization.Active-set", "identity.organization.active-set ", "identity.organization.active-set-all"} {
		alias := scope
		alias.Operation = action
		if _, err := counters.Prepare(alias, subject, alias.Now); err == nil {
			t.Fatal("unselected selection action acquired protected counters", action)
		}
	}
}
