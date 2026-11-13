package risk

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func TestOIDCProviderRegistrationRequiresExactProtectedAdmission(t *testing.T) {
	policy := testPolicy(t)
	scope := testContext()
	scope.Operation = "identity.sso.provider.register-oidc"
	subject := Subject{Actor: "organization-admin", Resource: "disabled-provider", Network: "192.0.2.1"}
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	for _, signals := range [][]Signal{nil, {testSignal(scope, "status", SignalClean)}, {testSignal(scope, "status", SignalClean), testSignal(scope, "captcha", SignalUnavailable)}} {
		assessment, err := policy.Assess(context.Background(), scope, signals)
		if err != nil || assessment.Decision.Action != Deny {
			t.Fatal("registration bypassed required current signals", err)
		}
	}
	assessment, err := policy.Assess(context.Background(), scope, []Signal{testSignal(scope, "status", SignalClean), testSignal(scope, "captcha", SignalClean)})
	if err != nil || assessment.Decision.Action != Allow {
		t.Fatal("clean registration cannot reach protected reservation", err)
	}
	command, err := counters.Prepare(scope, subject, scope.Now)
	if err != nil || command.Bindings().Phase != ReserveWithCommand || len(command.Bindings().Targets) != 4 || counters.Validate(command, scope, subject, scope.Now) != nil {
		t.Fatal("registration lacks original protected counter custody", err)
	}
	for _, change := range []func(*Context, *Subject){
		func(c *Context, _ *Subject) { c.Tenant = "foreign-tenant" },
		func(c *Context, _ *Subject) { c.Attempt = "foreign-command" },
		func(c *Context, _ *Subject) { c.Operation = "identity.organization.create" },
		func(_ *Context, s *Subject) { s.Actor = "foreign-admin" },
		func(_ *Context, s *Subject) { s.Resource = "another-provider" },
		func(_ *Context, s *Subject) { s.Network = "192.0.2.2" },
	} {
		changed, target := scope, subject
		change(&changed, &target)
		if counters.Validate(command, changed, target, scope.Now) == nil {
			t.Fatal("provider reservation transferred its original scope")
		}
	}
	if counters.Validate(command, scope, subject, scope.Now.Add(15*time.Minute)) == nil {
		t.Fatal("provider reservation renewed its original deadline")
	}
	for _, operation := range []Action{"identity.sso.provider.get", "identity.sso.provider.list", "identity.sso.provider.register-oauth2", "identity.sso.provider.Register-oidc", "identity.sso.provider.register-oidc "} {
		changed := scope
		changed.Operation = operation
		if _, err := counters.Prepare(changed, subject, scope.Now); err == nil {
			t.Fatal("unselected provider operation acquired mutation counters", operation)
		}
	}
}
