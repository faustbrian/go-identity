package postgres

import (
	"bytes"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func verificationMFAPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := passwordMFAPlanFixture(t)
	b.UserID, b.AnonymousFlowID = p.MFAContinuation.UserID, ""
	b.RecordID = "AgICAgICAgICAgICAgICAg"
	b.OperationID, b.SchemaID = "identity.email.verification-signin", "email-verification-signin"
	b.PolicyVersion = p.MFAContinuation.PolicyVersion
	previous := p.Feature.Contributor
	p.Feature.Contributor = ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}
	p.Feature.Operation = identity.FeatureOperation{Owner: "identity/email", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	for i, d := range p.Contributors {
		if d == previous {
			p.Contributors[i] = p.Feature.Contributor
		}
	}
	p.Lifecycle.AfterVersion = 1
	return b, p
}

func TestVerificationMFAPlanConservesSeparateOrigin(t *testing.T) {
	b, p := verificationMFAPlanFixture(t)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal("committed-verification primary cannot declare pending MFA", err)
	}
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || got.MFAContinuation == nil || *got.MFAContinuation != *p.MFAContinuation || got.Capability != nil || got.CapabilityIssuance == nil || got.CapabilityIssuance.Grants[0] != p.CapabilityIssuance.Grants[0] || got.Lifecycle.EventType != "mfa.challenge.created.v1" {
		t.Fatal("verification origin or child scope changed during restoration", err)
	}
	again, err := encodeFeaturePlan(b, [32]byte{1}, got)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("verification challenge is not canonical", err)
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated verification challenge accepted")
		}
	}
	foreign, _ := passwordMFAPlanFixture(t)
	if _, err := decodeFeaturePlan(foreign, [32]byte{1}, wire); err == nil {
		t.Fatal("verification primary reinterpreted as password proof")
	}
}

func TestVerificationMFAPlanRejectsScopeSubstitution(t *testing.T) {
	for name, mutate := range map[string]func(*identity.CommandBinding, *CommandPlan){
		"anonymous subject":                      func(b *identity.CommandBinding, _ *CommandPlan) { b.AnonymousFlowID = "AQEBAQEBAQEBAQEBAQEBAQ" },
		"missing subject":                        func(b *identity.CommandBinding, _ *CommandPlan) { b.UserID = "" },
		"missing confirmation parent":            func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = "" },
		"self parent":                            func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = string(b.CommandID) },
		"foreign selected subject":               func(_ *identity.CommandBinding, p *CommandPlan) { p.MFAContinuation.UserID = "foreign-user" },
		"session before factor":                  func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" },
		"invented same-work primary consumption": func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		"foreign issuer recipient": func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CapabilityIssuance.MFAContinuationUserID = "foreign-user"
		},
		"zero factor generation":    func(_ *identity.CommandBinding, p *CommandPlan) { p.MFAContinuation.FactorVersion = 0 },
		"foreign policy generation": func(b *identity.CommandBinding, _ *CommandPlan) { b.PolicyVersion++ },
		"foreign owner":             func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Contributor.Owner = "foreign/postgres" },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := verificationMFAPlanFixture(t)
			mutate(&b, &p)
			if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
				t.Fatal("foreign or session-producing verification challenge admitted")
			}
		})
	}
}

func TestVerificationMFAPlanFreezesGeneratedScope(t *testing.T) {
	b, final := verificationMFAPlanFixture(t)
	original := final
	original.CapabilityIssuance = nil
	original.Contributors = append([]ContributorDescriptor(nil), final.Contributors[:len(final.Contributors)-1]...)
	original.MFAContinuation = &MFAContinuationPlan{UserID: b.UserID, PolicyVersion: final.MFAContinuation.PolicyVersion, FactorVersion: final.MFAContinuation.FactorVersion}
	if !preparationFinalDeclaration(b, original, final) {
		t.Fatal("journal-owned child generation cannot finish verification preparation")
	}
	changed := final
	changed.MFAContinuation = cloneMFAContinuationPlan(final.MFAContinuation)
	changed.MFAContinuation.FactorVersion++
	if preparationFinalDeclaration(b, original, changed) {
		t.Fatal("restored verification challenge borrowed a newer factor generation")
	}
}

func FuzzVerificationMFAPlan(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa6})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		b, final := verificationMFAPlanFixture(t)
		initial := final
		initial.CapabilityIssuance = nil
		initial.Contributors = append([]ContributorDescriptor(nil), final.Contributors[:len(final.Contributors)-1]...)
		initial.MFAContinuation = &MFAContinuationPlan{UserID: b.UserID, PolicyVersion: final.MFAContinuation.PolicyVersion, FactorVersion: final.MFAContinuation.FactorVersion}
		for _, seed := range []CommandPlan{initial, final} {
			wire, err := encodeMFAContinuationPlanMode(b, [32]byte{1}, seed, true)
			if err != nil {
				t.Fatal("valid original verification declaration rejected", err)
			}
			for _, input := range [][]byte{wire, data} {
				got, err := decodeMFAContinuationPlanMode(b, [32]byte{1}, input, true)
				if err != nil {
					continue
				}
				again, err := encodeMFAContinuationPlanMode(b, [32]byte{1}, got, true)
				if err != nil || !bytes.Equal(again, input) || !validEmailVerificationMFAPlanMode(b, got, true) {
					t.Fatal("noncanonical or foreign verification origin accepted")
				}
				password, _ := passwordMFAPlanFixture(t)
				magic, _ := magicLinkMFAPlanFixture(t)
				for _, foreign := range []identity.CommandBinding{password, magic} {
					if _, err := decodeMFAContinuationPlanMode(foreign, [32]byte{1}, input, true); err == nil {
						t.Fatal("verification declaration reinterpreted as another primary")
					}
				}
				if ungeneratedMFAContinuation(got.MFAContinuation) {
					if _, err := decodeFeaturePlan(b, [32]byte{1}, input); err == nil {
						t.Fatal("ungenerated verification preparation admitted as execution")
					}
				}
			}
		}
	})
}
