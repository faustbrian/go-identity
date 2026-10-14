package postgres

import (
	"bytes"
	"crypto/sha256"
	identity "github.com/faustbrian/go-identity"
	"reflect"
	"testing"
)

func TestMagicLinkRequestAcceptanceConservesPreparedBranches(t *testing.T) {
	b, original, issued := magicLinkIssuanceFixture(t)
	original.Audits[0].RetentionClass = "protected"
	issued.Audits[0].RetentionClass = "protected"
	for _, p := range []CommandPlan{original, issued} {
		legacy, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal(err)
		}
		p.MagicLinkRequestAcceptance = true
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil || bytes.Equal(wire, legacy) {
			t.Fatal("neutral request branch not frozen", err)
		}
		got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		p.Digest = sha256.Sum256(wire)
		if err != nil || !reflect.DeepEqual(got, p) {
			t.Fatal("request branches changed on restore", err)
		}
		for i := range wire {
			if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
				t.Fatal("truncated acceptance admitted")
			}
		}
		p.MagicLinkRequestAcceptance = false
		after, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil || !bytes.Equal(legacy, after) {
			t.Fatal("historical request bytes changed", err)
		}
	}
	original.MagicLinkRequestAcceptance, issued.MagicLinkRequestAcceptance = true, true
	if !preparationFinalDeclaration(b, original, issued) {
		t.Fatal("original neutral branch lost")
	}
	issued.MagicLinkRequestAcceptance = false
	if preparationFinalDeclaration(b, original, issued) || preparationFinalDeclaration(b, issued, original) {
		t.Fatal("restoration changed neutral branch")
	}
	original.SignupAcceptance = true
	if _, err := encodeFeaturePlan(b, [32]byte{1}, original); err == nil {
		t.Fatal("password and magic-link acceptance conflated")
	}
}

func TestMagicLinkRequestAcceptanceIsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"password branch": func(_ *identity.CommandBinding, p *CommandPlan) { p.SignupAcceptance = true },
		"authenticated":   func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "user"; b.AnonymousFlowID = "" },
		"missing flow":    func(b *identity.CommandBinding, _ *CommandPlan) { b.AnonymousFlowID = "" },
		"foreign operation": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Operation.OperationID = "identity.password.reset-request"
		},
		"foreign owner": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.Owner = "identity/password/postgres"
		},
		"missing feature":   func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature = nil },
		"unprotected audit": func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		"changed lifecycle": func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "user.created.v1" },
		"changed version":   func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.AfterVersion = 1 },
		"wrong subject":     func(_ *identity.CommandBinding, p *CommandPlan) { p.SubjectType = "session" },
		"foreign issuance":  func(_ *identity.CommandBinding, p *CommandPlan) { p.CapabilityIssuance.MagicLinkRecipientUserID = "" },
		"foreign purpose": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].Purpose = "identity.password.reset-complete"
		},
	} {
		t.Run(name, func(t *testing.T) {
			b, _, p := magicLinkIssuanceFixture(t)
			p.MagicLinkRequestAcceptance = true
			p.Audits[0].RetentionClass = "protected"
			if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err != nil {
				t.Fatal("positive control", err)
			}
			mutate(&b, &p)
			if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
				t.Fatal("foreign neutral profile admitted")
			}
		})
	}
}

func FuzzMagicLinkRequestAcceptancePlan(f *testing.F) {
	f.Add([]byte{0xa2})
	f.Add(cborMap(map[string][]byte{"base": cborBytes([]byte{0xa2}), "profile": cborText(magicLinkRequestAcceptanceProfile)}))
	f.Fuzz(func(t *testing.T, wire []byte) {
		if len(wire) > 65537 {
			return
		}
		b, _, _ := magicLinkIssuanceFixture(t)
		p, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err == nil {
			canonical, err := encodeFeaturePlan(b, [32]byte{1}, p)
			if err != nil || !bytes.Equal(wire, canonical) {
				t.Fatal("accepted noncanonical request plan")
			}
		}
	})
}
