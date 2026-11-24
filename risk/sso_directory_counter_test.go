package risk

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestDirectorySyncStartResourceIsCanonicalAndStable(t *testing.T) {
	const want = "sso-directory-v1:59846f63082f79a6ff53aa7c80f5b280d6003afa40dd9ff74ffcce492b7098d3"
	got, err := DirectorySyncStartCounterResource("organization", "source", "provider")
	if err != nil || got != want {
		t.Fatal("canonical directory resource changed", err)
	}
	for _, ids := range [][3]string{{"other-organization", "source", "provider"}, {"organization", "other-source", "provider"}, {"organization", "source", "other-provider"}, {"organization", "provider", "source"}} {
		other, err := DirectorySyncStartCounterResource(ids[0], ids[1], ids[2])
		if err != nil || other == got {
			t.Fatal("different organization/source/provider shared the same resource", err)
		}
	}
	left, _ := DirectorySyncStartCounterResource("a", "bc", "d")
	right, _ := DirectorySyncStartCounterResource("ab", "c", "d")
	if left == right {
		t.Fatal("resource encoding lost field boundaries")
	}
	for _, bad := range []string{"", " source", "source ", "source\n", "source\x00", "é", strings.Repeat("x", 129)} {
		for field := range 3 {
			ids := [3]string{"organization", "source", "provider"}
			ids[field] = bad
			if resource, err := DirectorySyncStartCounterResource(ids[0], ids[1], ids[2]); err == nil || resource != "" {
				t.Fatal("invalid canonical directory scope obtained a resource")
			}
		}
	}
	maximum := strings.Repeat("x", 128)
	if resource, err := DirectorySyncStartCounterResource(maximum, maximum, maximum); err != nil || len(resource) > 128 {
		t.Fatal("maximum canonical IDs exceeded the bounded resource dimension", err)
	}
}

func TestDirectorySyncStartRequiresExactPrivilegedAdmission(t *testing.T) {
	policy := testPolicy(t)
	scope := testContext()
	scope.Operation = "identity.sso.directory-sync-start"
	scope.IndependentFactor = true
	subject := Subject{Actor: "directory-admin", Resource: "stable-directory-provider", Network: "192.0.2.1"}
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
	for _, signals := range [][]Signal{nil, {status}, {captcha}, {status, testSignal(scope, "captcha", SignalUnavailable)}} {
		assessment, err := policy.Assess(context.Background(), scope, signals)
		if err != nil || assessment.Decision.Action != Deny {
			t.Fatal("start bypassed required current signals", err)
		}
	}
	assessment, err := policy.Assess(context.Background(), scope, []Signal{status, captcha})
	if err != nil || assessment.Decision.Action != Allow {
		t.Fatal("clean start cannot reach protected reservation", err)
	}
	for _, change := range []func(*Signal){
		func(s *Signal) { s.Tenant = "other-tenant" },
		func(s *Signal) { s.Attempt = "other-attempt" },
		func(s *Signal) { s.Operation = "identity.sso.provider.enable" },
		func(s *Signal) { s.ExpiresAt = scope.Now },
	} {
		foreign := status
		change(&foreign)
		assessment, err := policy.Assess(context.Background(), scope, []Signal{foreign, captcha})
		if err == nil && assessment.Decision.Action != Deny {
			t.Fatal("foreign or expired signals admitted directory start")
		}
	}
	command, err := counters.Prepare(scope, subject, scope.Now)
	if err != nil {
		t.Fatal("start cannot prepare privileged counters", err)
	}
	binding := command.Bindings()
	want := []Dimension{TenantDimension, ActorDimension, ResourceDimension, NetworkDimension}
	if binding.Operation != scope.Operation || binding.Attempt != scope.Attempt || binding.Phase != ReserveWithCommand || len(binding.Targets) != len(want) || counters.Validate(command, scope, subject, scope.Now) != nil {
		t.Fatal("start lost original privileged reservation custody")
	}
	for i, dimension := range want {
		if binding.Targets[i].Dimension != dimension {
			t.Fatal("start omitted a privileged dimension", dimension)
		}
	}
	for _, change := range []func(*Context, *Subject){
		func(c *Context, _ *Subject) { c.Tenant = "other-tenant" },
		func(c *Context, _ *Subject) { c.Attempt = "other-attempt" },
		func(c *Context, _ *Subject) { c.Operation = "identity.sso.provider.enable" },
		func(_ *Context, s *Subject) { s.Actor = "other-admin" },
		func(_ *Context, s *Subject) { s.Resource = "other-source-provider" },
		func(_ *Context, s *Subject) { s.Network = "192.0.2.2" },
	} {
		other, target := scope, subject
		change(&other, &target)
		if counters.Validate(command, other, target, scope.Now) == nil {
			t.Fatal("start transferred original reservation scope")
		}
	}
	if counters.Validate(command, scope, subject, scope.Now.Add(15*time.Minute)) == nil {
		t.Fatal("start renewed original exclusive expiry")
	}
	for _, operation := range []Action{"identity.sso.directory-sync-apply", "identity.sso.directory-sync-cancel", "identity.sso.directory-sync-status", "identity.sso.directory-sync-Start", "identity.sso.directory-sync-start ", "identity.sso.directory-sync-start.extra"} {
		other := scope
		other.Operation = operation
		if _, err := counters.Prepare(other, subject, scope.Now); err == nil {
			t.Fatal("unselected operation acquired start counters", operation)
		}
	}
}
