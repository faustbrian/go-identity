package postgres

import (
	"bytes"
	"crypto/sha256"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func magicLinkConsumptionPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := emailVerificationPlanFixture(t)
	b.OperationID, b.SchemaID = "identity.magic-link.consume", "magic-link-consume"
	b.UserID, b.RecordID, b.AnonymousFlowID = "", "", "AQEBAQEBAQEBAQEBAQEBAQ"
	p.Feature.Operation = identity.FeatureOperation{Owner: "identity/magiclink", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	p.Feature.Contributor = ContributorDescriptor{Owner: "identity/magiclink/postgres", ContractID: "identity.magiclink", Version: 1}
	p.Contributors[3] = p.Feature.Contributor
	p.SubjectType = "authentication_attempt"
	p.Lifecycle = &LifecyclePlan{EventType: "session.created.v1"}
	p.Audits[0].EventType = "authentication.succeeded"
	p.Capability.Purpose = "identity.magic-link.consume"
	return b, p
}

func TestMagicLinkConsumptionPlanRoundTripAndRejectsProofFreeBase(t *testing.T) {
	b, p := magicLinkConsumptionPlanFixture(t)
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal("closed consuming login unavailable", err)
	}
	restored, err := decodeFeaturePlan(b, fp, wire)
	if err != nil || restored.Capability == nil || *restored.Capability != *p.Capability || restored.Digest != sha256.Sum256(wire) {
		t.Fatal("lost consumption custody", err)
	}
	again, err := encodeFeaturePlan(b, fp, restored)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("changed historical plan", err)
	}
	p.Capability = nil
	p.Contributors = p.Contributors[:len(p.Contributors)-1]
	if _, err := encodeFeaturePlan(b, fp, p); err == nil {
		t.Fatal("proof-free login admitted")
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, fp, wire[:i]); err == nil {
			t.Fatal("truncated plan admitted", i)
		}
	}
}

func TestMagicLinkConsumptionPlanRejectsForeignAndIncompleteProfiles(t *testing.T) {
	for name, change := range map[string]func(*CommandPlan){
		"missing proof":          func(p *CommandPlan) { p.Capability = nil },
		"foreign purpose":        func(p *CommandPlan) { p.Capability.Purpose = "identity.identifier.verify" },
		"missing counters":       func(p *CommandPlan) { p.CommandCounters = nil },
		"foreign schema":         func(p *CommandPlan) { p.Feature.Operation.SchemaID = "password-reset-complete" },
		"foreign owner":          func(p *CommandPlan) { p.Feature.Contributor.Owner = "identity/otp/postgres" },
		"unprotected audit":      func(p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		"wrong subject":          func(p *CommandPlan) { p.SubjectType = "user" },
		"wrong event":            func(p *CommandPlan) { p.Lifecycle.EventType = "identifier.verified.v1" },
		"kernel mutation":        func(p *CommandPlan) { p.Lifecycle.AfterVersion = 1 },
		"wrong maximum":          func(p *CommandPlan) { p.Capability.MaxUses = 2 },
		"fresh issuer":           func(p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		"fresh delivery":         func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"OTP substitution":       func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
		"wrong capability owner": func(p *CommandPlan) { p.Contributors[len(p.Contributors)-1].Version++ },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := magicLinkConsumptionPlanFixture(t)
			change(&p)
			if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
				t.Fatal("foreign consuming profile admitted")
			}
		})
	}
}

func FuzzMagicLinkConsumptionPlan(f *testing.F) {
	f.Add([]byte{0xa5})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 65536 {
			return
		}
		b, p := magicLinkConsumptionPlanFixture(t)
		fp := [32]byte{1}
		// Include a complete owned seed on every invocation so valid bounded
		// decoding and arbitrary hostile decoding share the same oracle.
		wire, err := encodeFeaturePlan(b, fp, p)
		if err != nil {
			t.Fatal(err)
		}
		inputs := [][]byte{wire, data}
		for _, input := range inputs {
			restored, err := decodeFeaturePlan(b, fp, input)
			if err != nil {
				continue
			}
			encoded, err := encodeFeaturePlan(b, fp, restored)
			if err != nil || !bytes.Equal(input, encoded) || restored.Capability == nil || restored.Capability.Purpose != "identity.magic-link.consume" || restored.Capability.MaxUses != 1 {
				t.Fatal("noncanonical or foreign consumption accepted")
			}
		}
	})
}
