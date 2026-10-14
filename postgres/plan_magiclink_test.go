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

func TestMagicLinkRegistrationPlanFreezesProspectiveCreation(t *testing.T) {
	b, p := magicLinkConsumptionPlanFixture(t)
	fp := [32]byte{1}
	old, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal(err)
	}
	p.MagicLinkRegistration = &MagicLinkRegistrationPlan{UserID: "prospective-user", IdentifierID: "prospective-email", CreationDigest: [32]byte{9}, EmailPossessionPolicyVersion: 3, CreationEventIndex: 1}
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil || bytes.Equal(old, wire) {
		t.Fatal("prospective creation was omitted from protected intent", err)
	}
	restored, err := decodeFeaturePlan(b, fp, wire)
	if err != nil || restored.MagicLinkRegistration == nil || *restored.MagicLinkRegistration != *p.MagicLinkRegistration {
		t.Fatal("prospective creation lost", err)
	}
	again, err := encodeFeaturePlan(b, fp, restored)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("registration intent changed on restoration", err)
	}
	for i := range wire {
		if _, err := decodeFeaturePlan(b, fp, wire[:i]); err == nil {
			t.Fatal("truncated signup declaration admitted", i)
		}
	}
	// A structural declaration without registered native ownership grants no
	// account creation. This must deny before registry access or SQL.
	var registry *ContributorRegistry
	p.Digest = sha256.Sum256(wire)
	if admitted, err := registry.admitFeaturePlan(b, fp, p); err == nil || admitted != nil {
		t.Fatal("unregistered signup acquired execution authority")
	}
	for name, mutate := range map[string]func(*MagicLinkRegistrationPlan){
		"retarget user":       func(r *MagicLinkRegistrationPlan) { r.UserID = "other-user" },
		"retarget identifier": func(r *MagicLinkRegistrationPlan) { r.IdentifierID = "other-email" },
		"replace creation":    func(r *MagicLinkRegistrationPlan) { r.CreationDigest[0]++ },
		"replace policy":      func(r *MagicLinkRegistrationPlan) { r.EmailPossessionPolicyVersion++ },
		"replace event slot":  func(r *MagicLinkRegistrationPlan) { r.CreationEventIndex++ },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			bad.MagicLinkRegistration = cloneMagicLinkRegistrationPlan(p.MagicLinkRegistration)
			mutate(bad.MagicLinkRegistration)
			digest, err := FeaturePlanDigest(b, fp, bad)
			if err != nil || digest == sha256.Sum256(wire) {
				t.Fatal("changed creation not bound", err)
			}
		})
	}
	foreignBinding, foreign := emailVerificationPlanFixture(t)
	foreign.MagicLinkRegistration = cloneMagicLinkRegistrationPlan(p.MagicLinkRegistration)
	if _, err := FeaturePlanDigest(foreignBinding, fp, foreign); err == nil {
		t.Fatal("registration dropped into foreign feature")
	}
	if _, err := KernelPlanDigest(b, fp, p); err == nil {
		t.Fatal("registration dropped into kernel profile")
	}
	for name, mutate := range map[string]func(*MagicLinkRegistrationPlan){
		"missing user":             func(r *MagicLinkRegistrationPlan) { r.UserID = "" },
		"missing identifier":       func(r *MagicLinkRegistrationPlan) { r.IdentifierID = "" },
		"missing creation":         func(r *MagicLinkRegistrationPlan) { r.CreationDigest = [32]byte{} },
		"missing policy":           func(r *MagicLinkRegistrationPlan) { r.EmailPossessionPolicyVersion = 0 },
		"duplicate lifecycle slot": func(r *MagicLinkRegistrationPlan) { r.CreationEventIndex = p.Lifecycle.EventIndex },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			r := *p.MagicLinkRegistration
			mutate(&r)
			bad.MagicLinkRegistration = &r
			if _, err := FeaturePlanDigest(b, fp, bad); err == nil {
				t.Fatal("incomplete creation admitted")
			}
		})
	}
	p.MagicLinkRegistration = nil
	again, err = encodeFeaturePlan(b, fp, p)
	if err != nil || !bytes.Equal(old, again) {
		t.Fatal("historical signin bytes changed", err)
	}
}

func TestMagicLinkConsumptionPlanSupportsAuthenticationAdmission(t *testing.T) {
	b, p := magicLinkConsumptionPlanFixture(t)
	p.CommandCounters = nil
	p.Contributors = append(p.Contributors[:4:4], p.Contributors[len(p.Contributors)-1])
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal("authentication-admitted magic-link requires credential-mutation counters", err)
	}
	restored, err := decodeFeaturePlan(b, fp, wire)
	if err != nil || restored.CommandCounters != nil || restored.Capability == nil || *restored.Capability != *p.Capability {
		t.Fatal("authentication admission lost original one-use input", err)
	}
	again, err := encodeFeaturePlan(b, fp, restored)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatal("authentication-admitted consuming plan changed", err)
	}
	p.Capability = nil
	p.Contributors = p.Contributors[:len(p.Contributors)-1]
	if _, err := encodeFeaturePlan(b, fp, p); err == nil {
		t.Fatal("authentication admission allowed proof-free login")
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
		p.MagicLinkRegistration = &MagicLinkRegistrationPlan{UserID: "prospective-user", IdentifierID: "prospective-email", CreationDigest: [32]byte{9}, EmailPossessionPolicyVersion: 3, CreationEventIndex: 1}
		signup, err := encodeFeaturePlan(b, fp, p)
		if err != nil {
			t.Fatal(err)
		}
		inputs := [][]byte{wire, signup, data}
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
