package postgres

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func magicLinkMFAPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := magicLinkConsumptionPlanFixture(t)
	p.MFAContinuation = &MFAContinuationPlan{ID: "AQEBAQEBAQEBAQEBAQEBAQ", UserID: "factor-user", ScopeDigest: [32]byte{7}, PolicyVersion: 2, FactorVersion: 3, IssuedAt: p.Capability.ExpiresAt.Add(-time.Minute), ExpiresAt: p.Capability.ExpiresAt}
	p.Lifecycle.EventType = "mfa.challenge.created.v1"
	p.CapabilityIssuance = issuanceTestPlan()
	p.CapabilityIssuance.MFAContinuationUserID = p.MFAContinuation.UserID
	p.CapabilityIssuance.Grants[0].CapabilityID = string(p.MFAContinuation.ID)
	p.CapabilityIssuance.Grants[0].Purpose = "identity.mfa.complete"
	p.CapabilityIssuance.Grants[0].ExpiresAt = p.MFAContinuation.ExpiresAt
	p.Contributors = append(p.Contributors, p.CapabilityIssuance.Contributor)
	return b, p
}

func TestMagicLinkMFAPlanFreezesChallengeInsteadOfSession(t *testing.T) {
	b, p := magicLinkMFAPlanFixture(t)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal("original one-use login cannot declare challenge-only child issuance", err)
	}
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || got.MFAContinuation == nil || *got.MFAContinuation != *p.MFAContinuation || got.Lifecycle.EventType != "mfa.challenge.created.v1" || got.Capability == nil || *got.Capability != *p.Capability || got.CapabilityIssuance == nil || got.CapabilityIssuance.Grants[0] != p.CapabilityIssuance.Grants[0] {
		t.Fatal("original proof or challenge issuance custody lost", err)
	}
	again, err := encodeFeaturePlan(b, [32]byte{1}, got)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("challenge declaration changed during recovery", err)
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated challenge declaration admitted", i)
		}
	}
	for name, mutate := range map[string]func(*CommandPlan){
		"session event":       func(p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" },
		"signup":              func(p *CommandPlan) { p.MagicLinkRegistration = &MagicLinkRegistrationPlan{} },
		"missing declaration": func(p *CommandPlan) { p.MFAContinuation = nil },
		"missing scope":       func(p *CommandPlan) { p.MFAContinuation.ScopeDigest = [32]byte{} },
		"missing subject":     func(p *CommandPlan) { p.MFAContinuation.UserID = "" },
		"missing factor":      func(p *CommandPlan) { p.MFAContinuation.FactorVersion = 0 },
		"missing policy":      func(p *CommandPlan) { p.MFAContinuation.PolicyVersion = 0 },
		"missing parent":      func(p *CommandPlan) { p.Capability = nil },
		"missing MFA subject": func(p *CommandPlan) { p.CapabilityIssuance.MFAContinuationUserID = "" },
		"foreign MFA subject": func(p *CommandPlan) { p.CapabilityIssuance.MFAContinuationUserID = "foreign-user" },
		"reuse parent replay": func(p *CommandPlan) {
			p.CapabilityIssuance.Grants[0].ReplayKeyVersion = p.Capability.ReplayKeyVersion
			p.CapabilityIssuance.Grants[0].ReplayDigest = p.Capability.ReplayDigest
		},
		"reuse parent proof": func(p *CommandPlan) { p.CapabilityIssuance.Grants[0].ProofFingerprint = p.Capability.ProofFingerprint },
		"different child":    func(p *CommandPlan) { p.CapabilityIssuance.Grants[0].CapabilityID = "different" },
		"different purpose":  func(p *CommandPlan) { p.CapabilityIssuance.Grants[0].Purpose = "identity.identifier.verify" },
		"multiple children": func(p *CommandPlan) {
			p.CapabilityIssuance.Grants = append(p.CapabilityIssuance.Grants, p.CapabilityIssuance.Grants[0])
		},
		"parent expiry extended": func(p *CommandPlan) {
			p.MFAContinuation.ExpiresAt = p.Capability.ExpiresAt.Add(time.Second)
			p.CapabilityIssuance.Grants[0].ExpiresAt = p.MFAContinuation.ExpiresAt
		},
		"five minute limit": func(p *CommandPlan) {
			p.MFAContinuation.IssuedAt = p.MFAContinuation.ExpiresAt.Add(-5*time.Minute - time.Second)
		},
		"alternate target": func(p *CommandPlan) { p.CapabilityIssuance.MagicLinkRecipientUserID = p.MFAContinuation.UserID },
	} {
		t.Run(name, func(t *testing.T) {
			b, bad := magicLinkMFAPlanFixture(t)
			mutate(&bad)
			if _, err := encodeFeaturePlan(b, [32]byte{1}, bad); err == nil {
				t.Fatal("incomplete or session-producing challenge admitted")
			}
		})
	}
	if _, err := KernelPlanDigest(b, [32]byte{1}, p); err == nil {
		t.Fatal("challenge admitted as ordinary kernel command")
	}
	var registry *ContributorRegistry
	if admitted, err := registry.admitFeaturePlan(b, [32]byte{1}, p); err == nil || admitted != nil {
		t.Fatal("structural challenge declaration granted execution")
	}
	for _, mutate := range []func(*MFAContinuationPlan){
		func(m *MFAContinuationPlan) { m.UserID = "other-user" },
		func(m *MFAContinuationPlan) { m.ScopeDigest[0]++ },
		func(m *MFAContinuationPlan) { m.PolicyVersion++ },
		func(m *MFAContinuationPlan) { m.FactorVersion++ },
		func(m *MFAContinuationPlan) { m.IssuedAt = m.IssuedAt.Add(-time.Second) },
	} {
		bad := p
		bad.MFAContinuation = cloneMFAContinuationPlan(p.MFAContinuation)
		mutate(bad.MFAContinuation)
		bad.CapabilityIssuance = cloneCapabilityIssuancePlan(p.CapabilityIssuance)
		bad.CapabilityIssuance.MFAContinuationUserID = bad.MFAContinuation.UserID
		changed, err := encodeFeaturePlan(b, [32]byte{1}, bad)
		if err != nil || bytes.Equal(changed, wire) {
			t.Fatal("changed challenge scope omitted from frozen declaration", err)
		}
	}
	copy := p
	copy.MFAContinuation = cloneMFAContinuationPlan(p.MFAContinuation)
	copy.MFAContinuation.ScopeDigest[0]++
	if copy.MFAContinuation.ScopeDigest == p.MFAContinuation.ScopeDigest {
		t.Fatal("caller mutation changes retained challenge")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		if diagnostic := fmt.Sprintf(verb, *p.MFAContinuation); !strings.Contains(diagnostic, "redacted") || strings.Contains(diagnostic, string(p.MFAContinuation.UserID)) || strings.Contains(diagnostic, string(p.MFAContinuation.ID)) {
			t.Fatal("challenge diagnostic leaked retained scope")
		}
	}
	if _, err := json.Marshal(p.MFAContinuation); err == nil {
		t.Fatal("general serialization exported challenge custody")
	}
}

func FuzzMagicLinkMFAPlan(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa6})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		b, p := magicLinkMFAPlanFixture(t)
		seed, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal(err)
		}
		original := p
		original.CapabilityIssuance = nil
		original.Contributors = p.Contributors[:len(p.Contributors)-1]
		preparation, err := encodeFeaturePlan(b, [32]byte{1}, original)
		if err != nil {
			t.Fatal(err)
		}
		ungenerated := original
		ungenerated.CommandCounters = nil
		ungenerated.Contributors = nil
		for _, d := range original.Contributors {
			if d.Owner != "identity/risk/postgres" {
				ungenerated.Contributors = append(ungenerated.Contributors, d)
			}
		}
		ungenerated.MFAContinuation = &MFAContinuationPlan{UserID: original.MFAContinuation.UserID, PolicyVersion: original.MFAContinuation.PolicyVersion, FactorVersion: original.MFAContinuation.FactorVersion}
		initial, err := encodeMagicLinkMFAPlanMode(b, [32]byte{1}, ungenerated, true)
		if err != nil {
			t.Fatal(err)
		}
		for _, input := range [][]byte{initial, data} {
			got, err := decodeMagicLinkMFAPlanMode(b, [32]byte{1}, input, true)
			if err != nil {
				continue
			}
			wire, err := encodeMagicLinkMFAPlanMode(b, [32]byte{1}, got, true)
			if err != nil || !bytes.Equal(wire, input) {
				t.Fatal("noncanonical preparation accepted")
			}
			if ungeneratedMFAContinuation(got.MFAContinuation) {
				if _, err := decodeFeaturePlan(b, [32]byte{1}, input); err == nil {
					t.Fatal("ungenerated preparation widened ordinary execution")
				}
			}
		}
		for _, input := range [][]byte{seed, preparation, data} {
			got, err := decodeFeaturePlan(b, [32]byte{1}, input)
			if err != nil {
				continue
			}
			wire, err := encodeFeaturePlan(b, [32]byte{1}, got)
			if err != nil || !bytes.Equal(input, wire) {
				t.Fatal("noncanonical challenge plan accepted")
			}
			if got.MFAContinuation != nil && !validMagicLinkMFAPlan(b, got) {
				t.Fatal("challenge widened original one-use custody")
			}
		}
	})
}
