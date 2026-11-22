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

func TestOIDCProviderUpdateRequiresItsOwnProtectedAdmission(t *testing.T) {
	policy := testPolicy(t)
	scope := testContext()
	scope.Operation = "identity.sso.provider.update"
	subject := Subject{Actor: "organization-admin", Resource: "disabled-provider", Network: "192.0.2.1"}
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}

	signals := []Signal{testSignal(scope, "status", SignalClean), testSignal(scope, "captcha", SignalClean)}
	for _, incomplete := range [][]Signal{nil, signals[:1]} {
		assessment, err := policy.Assess(context.Background(), scope, incomplete)
		if err != nil || assessment.Decision.Action != Deny {
			t.Fatalf("update without all required current signals: want deny, got %v (%v)", assessment.Decision.Action, err)
		}
	}
	assessment, err := policy.Assess(context.Background(), scope, signals)
	if err != nil || assessment.Decision.Action != Allow {
		t.Fatalf("clean update should reach protected reservation: got %v (%v)", assessment.Decision.Action, err)
	}
	command, err := counters.Prepare(scope, subject, scope.Now)
	if err != nil || command.Bindings().Phase != ReserveWithCommand || len(command.Bindings().Targets) != 4 || counters.Validate(command, scope, subject, scope.Now) != nil {
		t.Fatal("update did not receive its own tenant, actor, provider and network reservation", err)
	}

	registration := scope
	registration.Operation = "identity.sso.provider.register-oidc"
	if counters.Validate(command, registration, subject, scope.Now) == nil {
		t.Fatal("update reservation authorized provider registration")
	}
	for _, operation := range []Action{"identity.sso.provider.disable", "identity.sso.provider.credentials-rotate ", "identity.sso.provider.update "} {
		unselected := scope
		unselected.Operation = operation
		if _, err := counters.Prepare(unselected, subject, scope.Now); err == nil {
			t.Fatalf("unselected operation %q obtained provider update counters", operation)
		}
	}
}

func TestOIDCProviderEnableRequiresItsOwnProtectedAdmission(t *testing.T) {
	policy := testPolicy(t)
	scope := testContext()
	scope.Operation = "identity.sso.provider.enable"
	subject := Subject{Actor: "organization-admin", Resource: "disabled-provider", Network: "192.0.2.1"}
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	status := testSignal(scope, "status", SignalClean)
	captcha := testSignal(scope, "captcha", SignalClean)

	t.Run("current signals are mandatory without factor fallback", func(t *testing.T) {
		factorScope := scope
		factorScope.IndependentFactor = true
		for _, signals := range [][]Signal{nil, {status}, {captcha}, {status, testSignal(scope, "captcha", SignalUnavailable)}, {testSignal(scope, "status", SignalUnknown), captcha}} {
			assessment, err := policy.Assess(context.Background(), factorScope, signals)
			if err != nil || assessment.Decision.Action != Deny {
				t.Fatalf("enable without complete clean signals: want deny, got %v (%v)", assessment.Decision.Action, err)
			}
		}
	})
	t.Run("clean enable reaches protected admission", func(t *testing.T) {
		assessment, err := policy.Assess(context.Background(), scope, []Signal{status, captcha})
		if err != nil || assessment.Decision.Action != Allow {
			t.Fatalf("clean enable should reach protected reservation: got %v (%v)", assessment.Decision.Action, err)
		}
	})
	t.Run("foreign or expired signals cannot authorize enable", func(t *testing.T) {
		for _, change := range []func(*Signal){
			func(s *Signal) { s.Tenant = "foreign-tenant" },
			func(s *Signal) { s.Attempt = "foreign-command" },
			func(s *Signal) { s.Operation = "identity.sso.provider.update" },
			func(s *Signal) { s.ExpiresAt = scope.Now },
		} {
			foreign := status
			change(&foreign)
			assessment, err := policy.Assess(context.Background(), scope, []Signal{foreign, captcha})
			if err == nil && assessment.Decision.Action != Deny {
				t.Fatal("foreign or expired signal authorized provider enablement")
			}
		}
	})
	t.Run("reservation retains exact command and dimension custody", func(t *testing.T) {
		command, err := counters.Prepare(scope, subject, scope.Now)
		if err != nil {
			t.Fatalf("enable cannot prepare its own protected reservation: %v", err)
		}
		binding := command.Bindings()
		if binding.Operation != scope.Operation || binding.Tenant != scope.Tenant || binding.Attempt != scope.Attempt || binding.Phase != ReserveWithCommand || counters.Validate(command, scope, subject, scope.Now) != nil {
			t.Fatal("enable did not retain its original command scope")
		}
		wantDimensions := []Dimension{TenantDimension, ActorDimension, ResourceDimension, NetworkDimension}
		if len(binding.Targets) != len(wantDimensions) {
			t.Fatal("enable did not reserve exactly tenant, actor, provider and network")
		}
		for index, dimension := range wantDimensions {
			if binding.Targets[index].Dimension != dimension {
				t.Fatalf("enable counter %d has dimension %v, want %v", index, binding.Targets[index].Dimension, dimension)
			}
		}
		for _, change := range []func(*Context, *Subject){
			func(c *Context, _ *Subject) { c.Tenant = "foreign-tenant" },
			func(c *Context, _ *Subject) { c.Attempt = "foreign-command" },
			func(c *Context, _ *Subject) { c.Operation = "identity.sso.provider.register-oidc" },
			func(c *Context, _ *Subject) { c.Operation = "identity.sso.provider.update" },
			func(c *Context, _ *Subject) { c.Operation = "identity.sso.provider.credentials-rotate" },
			func(_ *Context, s *Subject) { s.Actor = "foreign-admin" },
			func(_ *Context, s *Subject) { s.Resource = "another-provider" },
			func(_ *Context, s *Subject) { s.Network = "192.0.2.2" },
		} {
			changed, target := scope, subject
			change(&changed, &target)
			if counters.Validate(command, changed, target, scope.Now) == nil {
				t.Fatal("enable reservation transferred its original operation or scope")
			}
		}
		if counters.Validate(command, scope, subject, scope.Now.Add(15*time.Minute)) == nil {
			t.Fatal("enable reservation renewed its original deadline")
		}
		for _, operation := range []Action{"identity.sso.provider.register-oidc", "identity.sso.provider.update", "identity.sso.provider.credentials-rotate"} {
			other := scope
			other.Operation = operation
			foreignCommand, err := counters.Prepare(other, subject, scope.Now)
			if err != nil {
				t.Fatal(err)
			}
			if counters.Validate(foreignCommand, scope, subject, scope.Now) == nil {
				t.Fatalf("%q reservation authorized provider enablement", operation)
			}
		}
	})
	t.Run("unselected actions and aliases stay closed", func(t *testing.T) {
		for _, operation := range []Action{"identity.sso.provider.disable", "identity.sso.provider.delete", "identity.sso.provider.get", "identity.sso.provider.list", "identity.sso.provider.register-oauth", "identity.sso.provider.register-saml", "identity.sso.provider.Enable", "identity.sso.provider.enable ", "identity.sso.provider.enable-oidc"} {
			other := scope
			other.Operation = operation
			assessment, err := policy.Assess(context.Background(), other, []Signal{testSignal(other, "status", SignalClean), testSignal(other, "captcha", SignalClean)})
			if err == nil && assessment.Decision.Action != Deny {
				t.Fatalf("unselected operation %q reached risk admission", operation)
			}
			if _, err := counters.Prepare(other, subject, scope.Now); err == nil {
				t.Fatalf("unselected operation %q obtained provider enable counters", operation)
			}
		}
	})
}

func TestOIDCProviderCredentialRotationUsesItsOwnProtectedAdmission(t *testing.T) {
	policy := testPolicy(t)
	scope := testContext()
	scope.Operation = "identity.sso.provider.credentials-rotate"
	subject := Subject{Actor: "organization-admin", Resource: "disabled-provider", Network: "192.0.2.1"}
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: policy, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	status := testSignal(scope, "status", SignalClean)
	captcha := testSignal(scope, "captcha", SignalClean)
	withoutCaptcha, err := policy.Assess(context.Background(), scope, []Signal{status})
	if err != nil || withoutCaptcha.Decision.Action != Deny {
		t.Fatalf("missing current signal granted rotation admission: %v (%v)", withoutCaptcha.Decision.Action, err)
	}
	current, err := policy.Assess(context.Background(), scope, []Signal{status, captcha})
	if err != nil || current.Decision.Action != Allow {
		t.Fatalf("exact credential rotation could not reach privileged admission: %v (%v)", current.Decision.Action, err)
	}
	command, err := counters.Prepare(scope, subject, scope.Now)
	if err != nil || command.Bindings().Phase != ReserveWithCommand || len(command.Bindings().Targets) != 4 || counters.Validate(command, scope, subject, scope.Now) != nil {
		t.Fatal("credential rotation did not receive exact protected counters", err)
	}
	for _, action := range []Action{"identity.sso.provider.update", "identity.sso.provider.register-oidc"} {
		other := scope
		other.Operation = action
		if counters.Validate(command, other, subject, scope.Now) == nil {
			t.Fatalf("credential rotation custody authorized %q", action)
		}
	}
}
