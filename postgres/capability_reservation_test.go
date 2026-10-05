package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

type capabilityReservationProbe struct {
	retained CapabilityReservationWork
}

func (*capabilityReservationProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1}
}
func (p *capabilityReservationProbe) ReserveCapability(ctx context.Context, w CapabilityReservationWork) error {
	p.retained = w
	_, err := w.Binding(p)
	return err
}
func (p *capabilityReservationProbe) RebindCapability(ctx context.Context, w CapabilityReservationWork) error {
	p.retained = w
	_, err := w.Binding(p)
	return err
}

func reservationPlanFixture(t *testing.T, extra Contributor) (*Coordinator, identity.Command, CommandPlan) {
	t.Helper()
	c, _, _ := coordinatorFixture(t)
	command := recordIdentifier(t, identity.IdentifierAttach, nil, nil)
	spec, _ := command.ChangeIdentifier()
	b := spec.Binding
	cp := CapabilityPlan{CapabilityID: spec.Proof.Payload().ID, Purpose: capability.Purpose(b.OperationID), ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: spec.Proof.EnvelopeDigest(), ExpiresAt: spec.Proof.Payload().ExpiresAt, MaxUses: 1}
	wire := queryFrozenPlan(t, b)
	p, err := decodeKernelPlan(b, [32]byte{1}, wire)
	if err != nil {
		t.Fatal(err)
	}
	p.Lifecycle = &LifecyclePlan{EventType: kernelLifecycleEvent(b.OperationID), EventIndex: 11, AfterVersion: 1}
	p.Capability = &cp
	entries := []Contributor{&registryContributor{p.Contributors[0]}, &planAuditContributor{registryContributor{p.Contributors[1]}}, &planLifecycleContributor{registryContributor{ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}}}, extra}
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	p.Contributors = c.registry.Descriptors()
	return c, command, p
}

func TestCapabilityReservationPrepareOwnsExactInput(t *testing.T) {
	c, command, p := reservationPlanFixture(t, &capabilityReservationProbe{})
	spec, _ := command.ChangeIdentifier()
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, p)
	if err != nil {
		t.Fatal("typed reservation rejected", err)
	}
	saved := *prepared.Capability
	p.Capability.ReplayDigest[0]++
	p.Lifecycle.AfterVersion++
	if *prepared.Capability != saved || prepared.Lifecycle.AfterVersion != 1 {
		t.Fatal("reservation input aliased caller")
	}
	q, _, admitted, err := c.prepare(spec.Binding, command, prepared)
	if err != nil || admitted.capability == nil || admitted.fingerprint != claimFingerprint(c.keys.retained[1], q.canonical) {
		t.Fatal("reservation fingerprint missing", err)
	}
	snap := admitted.snapshot()
	snap.Capability.CapabilityID = "foreign"
	if admitted.capability.CapabilityID != saved.CapabilityID {
		t.Fatal("admitted input alias")
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Capability = nil },
		func(p *CommandPlan) { p.Capability.CapabilityID = "foreign" },
		func(p *CommandPlan) { p.Capability.ExpiresAt = p.Capability.ExpiresAt.Add(time.Second) },
		func(p *CommandPlan) { p.Lifecycle.BeforeVersion = 1; p.Lifecycle.AfterVersion = 2 },
	} {
		candidate := prepared
		cp := *prepared.Capability
		candidate.Capability = &cp
		lp := *prepared.Lifecycle
		candidate.Lifecycle = &lp
		change(&candidate)
		if _, err := c.PrepareCommandPlan(spec.Binding, command, candidate); err == nil {
			t.Fatal("substituted signed input admitted")
		}
	}
	// Reservation is bookkeeping only: even an internally owned reservation
	// cannot expose domain Work before the rest of the typed phases exist.
	r := Reservation{state: &reservationState{coordinator: c, plan: admitted}}
	if _, err := c.Begin(context.Background(), r); err == nil || r.state.started.Load() {
		t.Fatal("incomplete workflow activated")
	}
}

func TestIdentifierReservationBindsExactAuthenticatedEnvelope(t *testing.T) {
	c, command, plan := reservationPlanFixture(t, &capabilityReservationProbe{})
	spec, _ := command.ChangeIdentifier()
	if spec.Proof.EnvelopeDigest() == ([32]byte{}) {
		t.Fatal("verified fixture lacks envelope identity")
	}
	if _, err := c.PrepareCommandPlan(spec.Binding, command, plan); err != nil {
		t.Fatal("exact signed envelope rejected", err)
	}
	for name, digest := range map[string][32]byte{
		"zero": {}, "foreign": {42},
	} {
		t.Run(name, func(t *testing.T) {
			copy := *plan.Capability
			copy.ProofFingerprint = digest
			changed := plan
			changed.Capability = &copy
			if _, err := c.PrepareCommandPlan(spec.Binding, command, changed); err == nil {
				t.Fatal("substituted envelope admitted")
			}
		})
	}
	// Re-signing preserves every payload field (including ID/use/expiry) while
	// producing a different authenticated envelope. No private token is logged.
	substituted := spec
	substituted.Proof = recordGrant(t, spec.Proof.Payload(), "other-proof-key")
	other, err := identity.NewIdentifierCommand(substituted)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.PrepareCommandPlan(spec.Binding, other, plan); err == nil {
		t.Fatal("another verified envelope reserved the original proof plan")
	}
	// Frozen history remains decodable. It never becomes current admission just
	// because its retained nonzero fingerprint has the expected structural shape.
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	prepared.Capability.ProofFingerprint = [32]byte{42}
	q, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	prepared.Digest, err = KernelPlanDigest(spec.Binding, fingerprint, prepared)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeKernelPlan(spec.Binding, fingerprint, prepared)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeKernelPlan(spec.Binding, fingerprint, wire)
	if err != nil || decoded.Capability.ProofFingerprint != ([32]byte{42}) {
		t.Fatal("historical envelope metadata rewritten", err)
	}
}

func TestCapabilityReservationZeroAndRedaction(t *testing.T) {
	var w CapabilityReservationWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero binding")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero exec")
	}
	if rows, err := w.Query(context.Background(), "SELECT 1"); err == nil || rows != nil {
		t.Fatal("zero query")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero time")
	}
	if fmt.Sprintf("%#v", w) != "postgres.CapabilityReservationWork(redacted)" {
		t.Fatal("handle formatting")
	}
	if _, err := json.Marshal(w); err == nil {
		t.Fatal("handle serialization")
	}
	var b CapabilityReservationBinding
	if fmt.Sprintf("%#v", b) != "postgres.CapabilityReservationBinding(redacted)" {
		t.Fatal("binding formatting")
	}
	if _, err := json.Marshal(b); err == nil {
		t.Fatal("binding serialization")
	}
}
