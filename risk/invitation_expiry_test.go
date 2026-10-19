package risk

import (
	"bytes"
	"context"
	"testing"
)

func TestInvitationExpiryRequiresProtectedAdmission(t *testing.T) {
	p := testPolicy(t)
	c := testContext()
	c.Operation = "identity.organization.invitation.expire"
	for _, signals := range [][]Signal{nil, {testSignal(c, "status", SignalClean)}, {testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalUnavailable)}} {
		assessment, err := p.Assess(context.Background(), c, signals)
		if err != nil || assessment.Decision.Action != Deny {
			t.Fatal("expiry without complete current signals admitted", err)
		}
	}
	assessment, err := p.Assess(context.Background(), c, []Signal{testSignal(c, "status", SignalClean), testSignal(c, "captcha", SignalClean)})
	if err != nil || assessment.Decision.Action != Allow {
		t.Fatal("verified expiry cannot reach protected reservation", err)
	}
	key, err := NewCounterDigestKey(7, bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	counters, err := NewCommandCounterPolicy(CommandCounterPolicyConfig{Policy: p, Keys: []CounterDigestKey{key}})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Actor: "actor", Resource: "invitation", Network: "192.0.2.1"}
	command, err := counters.Prepare(c, subject, c.Now)
	if err != nil || command.Bindings().Phase != ReserveWithCommand || len(command.Bindings().Targets) != 4 || counters.Validate(command, c, subject, c.Now) != nil {
		t.Fatal("expiry cannot reserve exact transaction-owned counters", err)
	}
	for _, change := range []func(*Context, *Subject){
		func(c *Context, _ *Subject) { c.Tenant = "other-tenant" },
		func(c *Context, _ *Subject) { c.Operation = "identity.organization.invitation.cancel" },
		func(_ *Context, s *Subject) { s.Actor = "other-actor" },
		func(_ *Context, s *Subject) { s.Resource = "other-invitation" },
		func(_ *Context, s *Subject) { s.Network = "192.0.2.2" },
	} {
		changed, target := c, subject
		change(&changed, &target)
		if counters.Validate(command, changed, target, c.Now) == nil {
			t.Fatal("expiry counter scope changed")
		}
	}
	for _, action := range []Action{"identity.organization.invitation.Expire", "identity.organization.invitation.expire ", "identity.organization.invitation.expire-all", "identity.organization.invitation.unknown"} {
		c.Operation = action
		if _, err := counters.Prepare(c, subject, c.Now); err == nil {
			t.Fatal("expiry alias admitted")
		}
	}
}
