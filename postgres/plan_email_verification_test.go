package postgres

import (
	"bytes"
	"crypto/sha256"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func emailVerificationPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	_, _, p := featurePlanFixture(t)
	b := codecBinding()
	b.OperationID = "identity.email.verification-confirm"
	b.SchemaID = "identity.email.verification-confirm.native-v1"
	b.RecordID = "identifier-a"
	p.Feature = &FeatureRegistration{
		Operation:   identity.FeatureOperation{Owner: "identity/email", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired},
		Contributor: ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1},
	}
	p.Contributors[3] = p.Feature.Contributor
	p.SubjectType = "identifier"
	p.Audits[0].EventType = "email.verified"
	p.Audits[0].RetentionClass = "protected"
	p.Lifecycle = &LifecyclePlan{EventType: "identifier.verified.v1", BeforeVersion: 1, AfterVersion: 2}
	p.CommandCounters = &CommandCounterPlan{PolicyVersion: 1, Fingerprint: [32]byte{5}}
	p.Contributors = append(p.Contributors,
		ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1},
		ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1})
	p.Capability = &CapabilityPlan{CapabilityID: "proof-a", Purpose: "identity.identifier.verify", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: [32]byte{4}, ExpiresAt: time.Unix(1800000000, 0).UTC(), MaxUses: 1}
	return b, p
}

func TestManagedEmailVerificationPlanCannotAliasSignup(t *testing.T) {
	b, p := emailVerificationPlanFixture(t)
	b.SchemaID = managedEmailVerificationOperation().SchemaID
	p.Feature.Operation = managedEmailVerificationOperation()
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || decoded.Feature == nil || decoded.Feature.Operation != managedEmailVerificationOperation() || decoded.Capability == nil || *decoded.Capability != *p.Capability {
		t.Fatal("managed plan lost original consumption scope", err)
	}
	for _, other := range [][]byte{bytes.Replace(wire, cborText("identity-managed-email-proof-v1"), cborText("identity-registration-email-proof-v1"), 1), append(bytes.Clone(wire), 0), wire[:len(wire)-1]} {
		if _, err := decodeFeaturePlan(b, [32]byte{1}, other); err == nil {
			t.Fatal("foreign or corrupt managed history admitted")
		}
	}
	registration := b
	registration.SchemaID = registrationEmailVerificationOperation().SchemaID
	if _, err := decodeFeaturePlan(registration, [32]byte{1}, wire); err == nil {
		t.Fatal("managed plan reinterpreted as signup")
	}
}

func TestManagedEmailChangePlanRequiresAtomicOldNotification(t *testing.T) {
	b, p := emailVerificationPlanFixture(t)
	b.OperationID, b.SchemaID = "identity.email.change-confirm", "identity.email.change-confirm.managed-v1"
	p.Feature.Operation.OperationID, p.Feature.Operation.SchemaID = b.OperationID, b.SchemaID
	p.Lifecycle.EventType = "identifier.primary-changed.v1"
	p.Delivery = deliveryTestPlan()
	p.Delivery.Intents[0].SubjectID = string(b.UserID)
	p.Delivery.Intents[0].Purpose = "identity.email.change-notification"
	p.Contributors = append(p.Contributors, p.Delivery.Contributor)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal("selected primary change with old notification denied", err)
	}
	decoded, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	if err != nil || decoded.Delivery == nil || decoded.Capability == nil || !reflect.DeepEqual(decoded.Contributors, p.Contributors) || *decoded.Capability != *p.Capability || !reflect.DeepEqual(decoded.Delivery, p.Delivery) {
		t.Fatal("change lost atomic notification or original proof", err)
	}
	// A delivery base cannot recursively contain a proof envelope. The
	// supported shape is exactly proof -> delivery -> ordinary feature.
	nestedDelivery := cborMap(map[string][]byte{"base": cborBytes(wire), "profile": cborText("identity-delivery-plan-v1"), "delivery": encodeDeliveryPlan(p.Delivery)})
	owner := ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
	nestedProof := cborMap(map[string][]byte{"base": cborBytes(nestedDelivery), "profile": cborText("identity-managed-email-change-proof-v1"), "version": cborUint(1), "capability": encodeCapabilityPlan(p.Capability), "contributor": cborMap(map[string][]byte{"owner": cborText(owner.Owner), "contract_id": cborText(owner.ContractID), "version": cborUint(uint64(owner.Version))})})
	if _, err := decodeFeaturePlan(b, [32]byte{1}, nestedProof); err == nil {
		t.Fatal("recursive proof/delivery base admitted")
	}
	p.Delivery = nil
	p.Contributors = p.Contributors[:len(p.Contributors)-1]
	if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
		t.Fatal("change silently omitted old notification")
	}
	b.OperationID, b.SchemaID = "identity.email.verification-confirm", "identity.email.verification-confirm.managed-v1"
	if _, err := decodeFeaturePlan(b, [32]byte{1}, wire); err == nil {
		t.Fatal("change became verification-only")
	}
}

func TestEmailVerificationConsumptionPlanRejectsForeignProfiles(t *testing.T) {
	for name, mutate := range map[string]func(*CommandPlan){
		"purpose alias":            func(p *CommandPlan) { p.Capability.Purpose = "identity.email.verification-confirm" },
		"foreign owner":            func(p *CommandPlan) { p.Feature.Operation.Owner = "identity/password" },
		"public schema":            func(p *CommandPlan) { p.Feature.Operation.SchemaID = "identity.email.verification-confirm.request" },
		"future schema":            func(p *CommandPlan) { p.Feature.Operation.SchemaVersion++ },
		"anonymous subject":        func(p *CommandPlan) { p.Feature.Operation.SubjectRequirement = identity.FeatureSubjectAnonymousFlow },
		"foreign adapter":          func(p *CommandPlan) { p.Feature.Contributor.ContractID = "foreign" },
		"missing counters":         func(p *CommandPlan) { p.CommandCounters = nil },
		"foreign risk evidence":    func(p *CommandPlan) { p.RiskEvidence = &RiskEvidencePlan{} },
		"OTP reinterpretation":     func(p *CommandPlan) { p.OTP = &OTPAttemptPlan{} },
		"fresh issuance":           func(p *CommandPlan) { p.CapabilityIssuance = issuanceTestPlan() },
		"new delivery":             func(p *CommandPlan) { p.Delivery = deliveryTestPlan() },
		"signup branch":            func(p *CommandPlan) { p.SignupAcceptance = true },
		"foreign subject":          func(p *CommandPlan) { p.SubjectType = "session" },
		"unprotected audit":        func(p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		"foreign event":            func(p *CommandPlan) { p.Lifecycle.EventType = "session.created.v1" },
		"zero predecessor":         func(p *CommandPlan) { p.Lifecycle.BeforeVersion = 0; p.Lifecycle.AfterVersion = 1 },
		"foreign capability owner": func(p *CommandPlan) { p.Contributors[len(p.Contributors)-1].Version++ },
		"duplicate capability":     func(p *CommandPlan) { p.Contributors = append(p.Contributors, p.Contributors[len(p.Contributors)-1]) },
		"missing owner":            func(p *CommandPlan) { p.Contributors = p.Contributors[:len(p.Contributors)-1] },
		"reusable proof":           func(p *CommandPlan) { p.Capability.MaxUses = 2 },
		"zero replay key":          func(p *CommandPlan) { p.Capability.ReplayKeyVersion = 0 },
		"zero envelope":            func(p *CommandPlan) { p.Capability.ProofFingerprint = [32]byte{} },
		"zero replay":              func(p *CommandPlan) { p.Capability.ReplayDigest = [32]byte{} },
	} {
		t.Run(name, func(t *testing.T) {
			b, p := emailVerificationPlanFixture(t)
			mutate(&p)
			if _, err := FeaturePlanDigest(b, [32]byte{1}, p); err == nil {
				t.Fatal("foreign or incomplete confirmation plan accepted")
			}
		})
	}
}

func TestEmailVerificationConsumptionPlanFreezesEveryProofField(t *testing.T) {
	b, p := emailVerificationPlanFixture(t)
	original, err := FeaturePlanDigest(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CapabilityPlan){
		func(p *CapabilityPlan) { p.CapabilityID = "proof-b" },
		func(p *CapabilityPlan) { p.ReplayDigest[1]++ },
		func(p *CapabilityPlan) { p.ReplayKeyVersion++ },
		func(p *CapabilityPlan) { p.ProofFingerprint[1]++ },
		func(p *CapabilityPlan) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
	} {
		_, changed := emailVerificationPlanFixture(t)
		mutate(changed.Capability)
		got, err := FeaturePlanDigest(b, [32]byte{1}, changed)
		if err != nil || got == original {
			t.Fatal("proof input omitted from confirmation fingerprint", err)
		}
	}
}

func TestEmailVerificationConsumptionPlanHostileHistory(t *testing.T) {
	b, p := emailVerificationPlanFixture(t)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	for end := range len(wire) {
		got, err := decodeFeaturePlan(b, [32]byte{1}, wire[:end])
		if err == nil || !reflect.DeepEqual(got, CommandPlan{}) {
			t.Fatal("truncated history escaped", end)
		}
	}
	for _, hostile := range [][]byte{
		append(append([]byte(nil), wire...), 0),
		bytes.Replace(wire, cborText("identity.identifier.verify"), cborText("identity.email.verification-confirm"), 1),
		bytes.Replace(wire, append(cborText("max_uses"), cborUint(1)...), append(cborText("max_uses"), cborUint(2)...), 1),
		bytes.Replace(wire, append(cborText("replay_key_version"), cborUint(1)...), append(cborText("replay_key_version"), cborUint(1<<32)...), 1),
		bytes.Replace(wire, cborText("identity-registration-email-proof-v1"), cborText("identity-capability-issuance-v1"), 1),
	} {
		if bytes.Equal(hostile, wire) {
			t.Fatal("ineffective hostile fixture")
		}
		got, err := decodeFeaturePlan(b, [32]byte{1}, hostile)
		if err == nil || !reflect.DeepEqual(got, CommandPlan{}) {
			t.Fatal("noncanonical or foreign proof history escaped")
		}
	}
	foreign := b
	foreign.TenantID = "foreign"
	if _, err := decodeFeaturePlan(foreign, [32]byte{1}, wire); err == nil {
		t.Fatal("foreign scope accepted")
	}
	if _, err := decodeFeaturePlan(b, [32]byte{2}, wire); err == nil {
		t.Fatal("foreign intent accepted")
	}
	// Neither a prepared declaration nor decoded history unlocks the domain.
	p.Digest = sha256.Sum256(wire)
	c, _, _ := featurePlanFixture(t)
	if admitted, err := c.registry.admitFeaturePlan(b, [32]byte{1}, p); err == nil || admitted != nil {
		t.Fatal("declaration bypassed missing atomic execution phases")
	}
}

func TestEmailVerificationConsumptionPlanPreservesSignedIdentity(t *testing.T) {
	b, p := emailVerificationPlanFixture(t)
	wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal("native email confirmation rejected its original one-time proof", err)
	}
	got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
	p.Digest = sha256.Sum256(wire)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("confirmation history lost original proof or action", err)
	}
	if got.Capability.Purpose != "identity.identifier.verify" || got.Feature.Operation.OperationID != "identity.email.verification-confirm" {
		t.Fatal("signed purpose was rewritten as confirmation action")
	}
}

func TestEmailVerificationConsumptionPlanCapabilityIDBounds(t *testing.T) {
	for _, size := range []int{128, 129, 256, 257} {
		b, p := emailVerificationPlanFixture(t)
		p.Capability.CapabilityID = strings.Repeat("a", size)
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if size > 256 {
			if err == nil {
				t.Fatal("oversized capability ID accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal("supported capability ID rejected", size, err)
		}
		got, err := decodeFeaturePlan(b, [32]byte{1}, wire)
		if err != nil || got.Capability == nil || got.Capability.CapabilityID != p.Capability.CapabilityID {
			t.Fatal("supported capability ID lost in history", size, err)
		}
	}
}
