package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type deliveryPlanProbe struct{ panicValidation bool }

func (*deliveryPlanProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.effects", Version: 1}
}
func (p *deliveryPlanProbe) ValidateDeliveryPlan(_ identity.CommandBinding, _ DeliveryPlan) error {
	if p.panicValidation {
		panic("private validation diagnostic")
	}
	return nil
}
func (*deliveryPlanProbe) PersistDelivery(context.Context, Work) error { return nil }
func (*deliveryPlanProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func deliveryTestPlan() *DeliveryPlan {
	return &DeliveryPlan{Contributor: (&deliveryPlanProbe{}).Descriptor(), Intents: []DeliveryIntentPlan{{EffectID: "effect-a", IntentDigest: [32]byte{1}, Purpose: "verification", SubjectID: "subject-a", TemplateID: "verify", TemplateVersion: 1, ProviderConfigVersion: 1, ExpiresAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)}}}
}

// A value owner with mutable fields cannot prove exact instance custody.
type noncomparableDeliveryProbe struct {
	*deliveryPlanProbe
	state []byte
}

func TestDeliveryAdmissionRejectsNoncomparableOwner(t *testing.T) {
	c, command, plan := coordinatorFixture(t)
	owner := noncomparableDeliveryProbe{deliveryPlanProbe: &deliveryPlanProbe{}, state: []byte{1}}
	entries := make([]Contributor, 0, len(c.registry.state.entries)+1)
	for _, entry := range c.registry.state.entries {
		entries = append(entries, entry.contributor)
	}
	entries = append(entries, owner)
	registry, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = registry
	plan.Contributors = registry.Descriptors()
	plan.Delivery = deliveryTestPlan()
	if _, err := c.PrepareCommandPlan(codecBinding(), command, plan); err == nil {
		t.Fatal("unusable delivery owner admitted before durable reservation")
	}
}

// This proves frozen declaration/recovery vocabulary, not durable admission.
// Real PostgreSQL tests must separately prove original-mutation atomicity.
func TestFeatureDeliveryDeclarationRetainsOriginalCommand(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	descriptor := ContributorDescriptor{Owner: "identity/delivery/postgres", ContractID: "identity.delivery.effects", Version: 1}
	plan.Contributors = append(plan.Contributors, descriptor)
	plan.Delivery = &DeliveryPlan{Contributor: descriptor, Intents: []DeliveryIntentPlan{{
		EffectID: "delivery-effect-a", EffectIndex: 0, IntentDigest: [32]byte{7},
		Purpose: "security-notification", SubjectID: string(spec.Binding.UserID),
		TemplateID: "security-notification", TemplateVersion: 1,
		ProviderConfigVersion: 1, ExpiresAt: time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC),
	}}}
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, plan)
	if err != nil {
		t.Fatal("original feature must admit its declared delivery participant", err)
	}
	got, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
	plan.Digest = sha256.Sum256(wire)
	if err != nil || !reflect.DeepEqual(got, plan) {
		t.Fatal("recovery lost original command or delivery declaration", err)
	}
	for _, mutate := range []func(*DeliveryIntentPlan){
		func(p *DeliveryIntentPlan) { p.EffectID = "delivery-effect-b" },
		func(p *DeliveryIntentPlan) { p.EffectIndex++ },
		func(p *DeliveryIntentPlan) { p.IntentDigest[0]++ },
		func(p *DeliveryIntentPlan) { p.Purpose = "verification" },
		func(p *DeliveryIntentPlan) { p.SubjectID = "different-resource" },
		func(p *DeliveryIntentPlan) { p.TemplateID = "different-template" },
		func(p *DeliveryIntentPlan) { p.TemplateVersion++ },
		func(p *DeliveryIntentPlan) { p.ProviderConfigVersion++ },
		func(p *DeliveryIntentPlan) { p.ExpiresAt = p.ExpiresAt.Add(time.Microsecond) },
	} {
		changed := plan
		copy := *plan.Delivery
		copy.Intents = append([]DeliveryIntentPlan(nil), copy.Intents...)
		changed.Delivery = &copy
		mutate(&changed.Delivery.Intents[0])
		digest, err := FeaturePlanDigest(spec.Binding, [32]byte{1}, changed)
		if err != nil || digest == plan.Digest {
			t.Fatal("delivery input omitted from original command declaration", err)
		}
	}
}

func TestDeliveryDeclarationRejectsMalformedAndOwnsCopies(t *testing.T) {
	for _, change := range []func(*DeliveryPlan){
		func(p *DeliveryPlan) { p.Contributor.Version++ },
		func(p *DeliveryPlan) { p.Intents = nil },
		func(p *DeliveryPlan) { p.Intents = make([]DeliveryIntentPlan, 17) },
		func(p *DeliveryPlan) { p.Intents[0].EffectID = "" },
		func(p *DeliveryPlan) { p.Intents[0].EffectID = strings.Repeat("x", 129) },
		func(p *DeliveryPlan) { p.Intents[0].IntentDigest = [32]byte{} },
		func(p *DeliveryPlan) { p.Intents[0].Purpose = "invalid purpose" },
		func(p *DeliveryPlan) { p.Intents[0].SubjectID = "" },
		func(p *DeliveryPlan) { p.Intents[0].TemplateVersion = 0 },
		func(p *DeliveryPlan) { p.Intents[0].ProviderConfigVersion = 0 },
		func(p *DeliveryPlan) { p.Intents[0].ExpiresAt = time.Time{} },
		func(p *DeliveryPlan) { p.Intents[0].ExpiresAt = time.Unix(-1, 0) },
		func(p *DeliveryPlan) { p.Intents[0].ExpiresAt = p.Intents[0].ExpiresAt.Add(time.Nanosecond) },
		func(p *DeliveryPlan) { v := p.Intents[0]; v.EffectIndex = 1; p.Intents = append(p.Intents, v) },
		func(p *DeliveryPlan) { v := p.Intents[0]; v.EffectID = "effect-b"; p.Intents = append(p.Intents, v) },
	} {
		p := deliveryTestPlan()
		change(p)
		if validDeliveryPlan(p) {
			t.Fatal("malformed delivery accepted")
		}
	}
	c, command, p := coordinatorFixture(t)
	probe := &deliveryPlanProbe{}
	entries := []Contributor{}
	for _, entry := range c.registry.state.entries {
		entries = append(entries, entry.contributor)
	}
	entries = append(entries, probe)
	r, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = r
	p.Contributors = r.Descriptors()
	p.Delivery = deliveryTestPlan()
	b := codecBinding()
	prepared, err := c.PrepareCommandPlan(b, command, p)
	if err != nil {
		t.Fatal(err)
	}
	p.Delivery.Intents[0].TemplateVersion++
	if prepared.Delivery.Intents[0].TemplateVersion != 1 {
		t.Fatal("prepared delivery aliases caller")
	}
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	fp := claimFingerprint([32]byte{1}, q.canonical)
	wire, err := encodeKernelPlan(b, fp, prepared)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeKernelPlan(b, fp, wire)
	if err != nil || !reflect.DeepEqual(got, prepared) {
		t.Fatal("kernel delivery round trip", err)
	}
	for i := range wire {
		if _, err := decodeKernelPlan(b, fp, wire[:i]); err == nil {
			t.Fatal("truncated delivery plan accepted")
		}
	}
	oversized := bytes.Replace(wire, append(cborText("intents"), 0x81), append(cborText("intents"), 0x98, 17), 1)
	if bytes.Equal(oversized, wire) {
		t.Fatal("unexercised hostile count")
	}
	if _, err := decodeKernelPlan(b, fp, oversized); err == nil {
		t.Fatal("oversized delivery count accepted")
	}
	probe.panicValidation = true
	if _, err := c.PrepareCommandPlan(b, command, prepared); err == nil {
		t.Fatal("validator panic admitted")
	}
}

func TestDeliveryCustodyCopiesAndInvocationLifetime(t *testing.T) {
	p := &deliveryPlanProbe{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := Work{state: &workState{ctx: ctx, cancel: cancel, delivery: &workDelivery{plan: deliveryTestPlan(), envelopes: make(map[uint16]DeliveryEnvelope)}}}
	input := DeliveryEnvelope{KeyID: "key-a", Ciphertext: []byte{1, 2, 3}}
	if err := w.StageDelivery(input); err != nil {
		t.Fatal(err)
	}
	input.Ciphertext[0] = 9
	if _, err := w.StagedDelivery(p); err == nil {
		t.Fatal("noninvoked ciphertext access")
	}
	w.state.delivery.invocation = p
	values, err := w.StagedDelivery(p)
	if err != nil || !bytes.Equal(values[0].Ciphertext, []byte{1, 2, 3}) {
		t.Fatal("staging borrowed ciphertext", err)
	}
	values[0].Ciphertext[0] = 8
	values, err = w.StagedDelivery(p)
	if err != nil || values[0].Ciphertext[0] != 1 {
		t.Fatal("read snapshot aliases custody")
	}
	if _, _, err := w.DeliveryScope(&deliveryPlanProbe{}); err == nil {
		t.Fatal("foreign instance acquired custody")
	}
	if got := fmt.Sprintf("%+v", input); strings.Contains(got, "key-a") || strings.Contains(got, "[9 2 3]") {
		t.Fatal("custody diagnostic exposed")
	}
	if _, err := json.Marshal(input); err == nil {
		t.Fatal("custody serialization allowed")
	}
	w.state.delivery.invocation = nil
	if err := w.StageDelivery(input); err == nil {
		t.Fatal("duplicate staging accepted")
	}
	invalidateWork(w)
	if len(w.state.delivery.envelopes) != 0 {
		t.Fatal("closed Work retained ciphertext references")
	}
	if _, _, err := w.DeliveryScope(p); err == nil {
		t.Fatal("closed delivery Work accepted")
	}
}

func TestDeliveryOwnerCheckedStagingRejectsUnenlistedInstance(t *testing.T) {
	owner, foreign := &deliveryPlanProbe{}, &deliveryPlanProbe{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := Work{state: &workState{ctx: ctx, cancel: cancel,
		delivery:  &workDelivery{plan: deliveryTestPlan(), envelopes: make(map[uint16]DeliveryEnvelope)},
		execution: &domainExecution{reservation: &reservationState{plan: &admittedKernelPlan{contributors: []registeredContributor{{descriptor: owner.Descriptor(), contributor: owner}}}}},
	}}
	input := DeliveryEnvelope{KeyID: "key-a", Ciphertext: []byte{1, 2, 3}}
	if err := w.StageDeliveryFor(foreign, input); err == nil || len(w.state.delivery.envelopes) != 0 {
		t.Fatal("unenlisted instance acquired staging authority")
	}
	if err := w.StageDeliveryFor(owner, input); err != nil {
		t.Fatal("exact original owner rejected", err)
	}
	input.Ciphertext[0] = 9
	if w.state.delivery.envelopes[0].Ciphertext[0] != 1 {
		t.Fatal("owner staging borrowed ciphertext")
	}
	invalidateWork(w)
	if err := w.StageDeliveryFor(owner, input); err == nil {
		t.Fatal("closed Work retained staging authority")
	}
}
