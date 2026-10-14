package postgres

import (
	"bytes"
	"testing"
	"time"
)

func TestMagicLinkMFAPreparationConservesOriginalChallenge(t *testing.T) {
	b, final := magicLinkMFAPlanFixture(t)
	original := final
	original.CapabilityIssuance = nil
	original.Contributors = append([]ContributorDescriptor(nil), final.Contributors[:len(final.Contributors)-1]...)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, original)
	if err != nil {
		t.Fatal("original challenge cannot prepare without signing a child before ownership", err)
	}
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || got.MFAContinuation == nil || *got.MFAContinuation != *original.MFAContinuation || got.CapabilityIssuance != nil || *got.Capability != *original.Capability {
		t.Fatal("original challenge scope changed", err)
	}
	again, err := encodeFeaturePlan(b, [32]byte{1}, got)
	if err != nil || !bytes.Equal(wire, again) || preparationProtected(original) || !preparationFinalDeclaration(b, original, final) {
		t.Fatal("generated child cannot conserve its original preparation", err)
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated original challenge accepted", i)
		}
	}
	for name, mutate := range map[string]func(*CommandPlan){
		"removed challenge": func(p *CommandPlan) { p.MFAContinuation = nil },
		"changed subject":   func(p *CommandPlan) { p.MFAContinuation.UserID = "other-user" },
		"changed scope":     func(p *CommandPlan) { p.MFAContinuation.ScopeDigest[0]++ },
		"changed factor":    func(p *CommandPlan) { p.MFAContinuation.FactorVersion++ },
		"changed policy":    func(p *CommandPlan) { p.MFAContinuation.PolicyVersion++ },
		"changed ID": func(p *CommandPlan) {
			p.MFAContinuation.ID = "AgICAgICAgICAgICAgICAg"
			p.CapabilityIssuance.Grants[0].CapabilityID = string(p.MFAContinuation.ID)
		},
		"renewed issue time": func(p *CommandPlan) { p.MFAContinuation.IssuedAt = p.MFAContinuation.IssuedAt.Add(time.Second) },
		"renewed expiry": func(p *CommandPlan) {
			p.MFAContinuation.ExpiresAt = p.MFAContinuation.ExpiresAt.Add(time.Second)
			p.CapabilityIssuance.Grants[0].ExpiresAt = p.MFAContinuation.ExpiresAt
		},
		"replaced parent": func(p *CommandPlan) { p.Capability.ProofFingerprint[0]++ },
		"removed child": func(p *CommandPlan) {
			p.CapabilityIssuance = nil
			p.Contributors = p.Contributors[:len(p.Contributors)-1]
		},
		"different purpose": func(p *CommandPlan) { p.CapabilityIssuance.Grants[0].Purpose = "identity.identifier.verify" },
		"session instead":   func(p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" },
		"added delivery": func(p *CommandPlan) {
			p.Delivery = deliveryTestPlan()
			p.Contributors = append(p.Contributors, p.Delivery.Contributor)
		},
	} {
		t.Run(name, func(t *testing.T) {
			bad := final
			bad.MFAContinuation = cloneMFAContinuationPlan(final.MFAContinuation)
			bad.CapabilityIssuance = cloneCapabilityIssuancePlan(final.CapabilityIssuance)
			proof, lifecycle := *final.Capability, *final.Lifecycle
			bad.Capability, bad.Lifecycle = &proof, &lifecycle
			mutate(&bad)
			if preparationFinalDeclaration(b, original, bad) {
				t.Fatal("restoration changed original challenge authority")
			}
		})
	}
	_, signin := magicLinkConsumptionPlanFixture(t)
	if preparationFinalDeclaration(b, signin, final) {
		t.Fatal("signin restoration introduced MFA child issuance")
	}
	for _, mutate := range []func(*MFAContinuationPlan){
		func(m *MFAContinuationPlan) { m.ID = "" },
		func(m *MFAContinuationPlan) { m.UserID = "" },
		func(m *MFAContinuationPlan) { m.ScopeDigest = [32]byte{} },
		func(m *MFAContinuationPlan) { m.FactorVersion = 0 },
		func(m *MFAContinuationPlan) { m.PolicyVersion = 0 },
		func(m *MFAContinuationPlan) { m.IssuedAt = time.Time{} },
		func(m *MFAContinuationPlan) { m.ExpiresAt = m.ExpiresAt.Add(time.Second) },
	} {
		bad := original
		bad.MFAContinuation = cloneMFAContinuationPlan(original.MFAContinuation)
		mutate(bad.MFAContinuation)
		if _, err := encodeFeaturePlan(b, [32]byte{1}, bad); err == nil {
			t.Fatal("missing child issuance bypassed original challenge bounds")
		}
	}
}
