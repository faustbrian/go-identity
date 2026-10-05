package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

type issuancePlanProbe struct{ panicValidation bool }

func (*issuancePlanProbe) Descriptor() ContributorDescriptor { return issuanceTestPlan().Contributor }
func (p *issuancePlanProbe) ValidateCapabilityIssuance(_ identity.CommandBinding, _ CapabilityIssuancePlan) error {
	if p.panicValidation {
		panic("private validation diagnostic")
	}
	return nil
}
func (*issuancePlanProbe) PersistCapabilityIssuance(context.Context, CapabilityIssuanceWork) error {
	return nil
}
func (*issuancePlanProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func issuanceTestPlan() *CapabilityIssuancePlan {
	return &CapabilityIssuancePlan{Contributor: ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.issuance", Version: 1}, Grants: []CapabilityPlan{{CapabilityID: "issued-a", Purpose: "identity.identifier.verify", ReplayKeyVersion: 1, ReplayDigest: [32]byte{1}, ProofFingerprint: [32]byte{2}, ExpiresAt: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC), MaxUses: 1}}}
}

func TestIssuancePlanFeatureDeliveryRoundTripAndBounds(t *testing.T) {
	_, command, p := featurePlanFixture(t)
	spec, _ := command.Feature()
	p.CapabilityIssuance = issuanceTestPlan()
	p.Contributors = append(p.Contributors, p.CapabilityIssuance.Contributor)
	p.Delivery = deliveryTestPlan()
	p.Contributors = append(p.Contributors, p.Delivery.Contributor)
	wire, err := encodeFeaturePlan(spec.Binding, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	p.Digest = sha256.Sum256(wire)
	got, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("combined effect history lost", err)
	}
	for _, mutate := range []func(*CapabilityIssuancePlan){
		func(v *CapabilityIssuancePlan) { v.Contributor.Version++ },
		func(v *CapabilityIssuancePlan) { v.Grants = nil },
		func(v *CapabilityIssuancePlan) { v.Grants = make([]CapabilityPlan, 17) },
		func(v *CapabilityIssuancePlan) { v.Grants[0].MaxUses++ },
		func(v *CapabilityIssuancePlan) { v.Grants[0].ReplayDigest = [32]byte{} },
		func(v *CapabilityIssuancePlan) { v.Grants[0].ProofFingerprint = [32]byte{} },
		func(v *CapabilityIssuancePlan) { v.Grants[0].ReplayKeyVersion = 0 },
		func(v *CapabilityIssuancePlan) { v.Grants[0].ExpiresAt = v.Grants[0].ExpiresAt.Add(time.Microsecond) },
		func(v *CapabilityIssuancePlan) { v.Grants[0].ExpiresAt = time.Time{} },
		func(v *CapabilityIssuancePlan) { v.Grants = append(v.Grants, v.Grants[0]) },
	} {
		bad := cloneCapabilityIssuancePlan(p.CapabilityIssuance)
		mutate(bad)
		if validCapabilityIssuancePlan(bad) {
			t.Fatal("malformed issuance admitted")
		}
	}
	for i := 0; i < len(wire); i++ {
		if _, err := decodeFeaturePlan(spec.Binding, [32]byte{1}, wire[:i]); err == nil {
			t.Fatal("truncated issuance history accepted")
		}
	}
}

func TestIssuanceAdmissionOwnsCopiesAndRejectsForeignOwner(t *testing.T) {
	c, command, p := coordinatorFixture(t)
	owner := &issuancePlanProbe{}
	entries := make([]Contributor, 0, len(c.registry.state.entries)+1)
	for _, entry := range c.registry.state.entries {
		entries = append(entries, entry.contributor)
	}
	entries = append(entries, owner)
	r, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = r
	p.Contributors = r.Descriptors()
	p.CapabilityIssuance = issuanceTestPlan()
	frozen, err := c.PrepareCommandPlan(codecBinding(), command, p)
	if err != nil {
		t.Fatal("issuance contributor rejected", err)
	}
	p.CapabilityIssuance.Grants[0].CapabilityID = "caller-mutation"
	if frozen.CapabilityIssuance.Grants[0].CapabilityID != "issued-a" {
		t.Fatal("caller mutation changed frozen issuance")
	}
	owner.panicValidation = true
	if _, err := c.PrepareCommandPlan(codecBinding(), command, p); err == nil {
		t.Fatal("panicking issuer admitted")
	}
	if _, err := (CapabilityIssuanceWork{}).Binding(owner); err == nil {
		t.Fatal("zero invocation accepted")
	}
	if _, err := (CapabilityIssuanceWork{}).Grants(owner); err == nil {
		t.Fatal("zero custody accepted")
	}
	if _, err := (CapabilityIssuanceWork{}).Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero SQL accepted")
	}
}

func TestIssuancePlanPreservesOriginalCommandAndHistoricalBytes(t *testing.T) {
	b := codecBinding()
	_, _, original := coordinatorFixture(t)
	before, err := encodeKernelPlan(b, [32]byte{1}, original)
	if err != nil {
		t.Fatal(err)
	}
	p := original
	p.CapabilityIssuance = issuanceTestPlan()
	p.Contributors = append(append([]ContributorDescriptor(nil), p.Contributors...), p.CapabilityIssuance.Contributor)
	wire, err := encodeKernelPlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal("original command issuance declaration rejected", err)
	}
	p.Digest = sha256.Sum256(wire)
	got, err := decodeKernelPlan(b, [32]byte{1}, wire)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("issuance declaration lost during recovery", err)
	}
	for _, mutate := range []func(*CapabilityPlan){
		func(v *CapabilityPlan) { v.CapabilityID = "issued-b" },
		func(v *CapabilityPlan) { v.Purpose = capability.Purpose("identity.identifier.attach") },
		func(v *CapabilityPlan) { v.ReplayKeyVersion++ },
		func(v *CapabilityPlan) { v.ReplayDigest[0]++ },
		func(v *CapabilityPlan) { v.ProofFingerprint[0]++ },
		func(v *CapabilityPlan) { v.ExpiresAt = v.ExpiresAt.Add(time.Second) },
	} {
		changed := p
		changed.CapabilityIssuance = cloneCapabilityIssuancePlan(p.CapabilityIssuance)
		mutate(&changed.CapabilityIssuance.Grants[0])
		newWire, err := encodeKernelPlan(b, [32]byte{1}, changed)
		if err != nil || bytes.Equal(newWire, wire) {
			t.Fatal("issuance input omitted from original frozen plan", err)
		}
	}
	after, err := encodeKernelPlan(b, [32]byte{1}, original)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("nil issuance changed historical bytes", err)
	}
}
