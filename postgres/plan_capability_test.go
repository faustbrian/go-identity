package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
)

func capabilityPlanFixture(t testing.TB) (CommandPlan, []byte) {
	t.Helper()
	b := codecBinding()
	b.OperationID = "identity.identifier.attach"
	b.RecordID = "identifier-a"
	p, err := decodeKernelPlan(b, [32]byte{1}, queryFrozenPlan(t, b))
	if err != nil {
		t.Fatal(err)
	}
	p.Lifecycle = &LifecyclePlan{EventType: kernelLifecycleEvent(b.OperationID), EventIndex: 11, AfterVersion: 1}
	p.Capability = &CapabilityPlan{CapabilityID: "proof-a", Purpose: capability.Purpose(b.OperationID), ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: [32]byte{4}, ExpiresAt: time.Unix(1800000000, 0).UTC(), MaxUses: 1}
	p.Contributors = append(p.Contributors, ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1}, ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1})
	wire, err := encodeKernelPlan(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	return p, wire
}

func TestCapabilityPlanRoundTripAndSubstitution(t *testing.T) {
	p, wire := capabilityPlanFixture(t)
	b := codecBinding()
	b.OperationID = "identity.identifier.attach"
	b.RecordID = "identifier-a"
	original, err := KernelPlanDigest(b, [32]byte{1}, p)
	if err != nil {
		t.Fatal(err)
	}
	p.Digest = original
	got, err := decodeKernelPlan(b, [32]byte{1}, wire)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("capability declaration lost", err)
	}
	for _, change := range []func(*CapabilityPlan){
		func(p *CapabilityPlan) { p.CapabilityID = "other" },
		func(p *CapabilityPlan) { p.ReplayDigest[1]++ },
		func(p *CapabilityPlan) { p.ReplayKeyVersion++ },
		func(p *CapabilityPlan) { p.ProofFingerprint[1]++ },
		func(p *CapabilityPlan) { p.ExpiresAt = p.ExpiresAt.Add(time.Second) },
	} {
		changed := p
		cp := *p.Capability
		changed.Capability = &cp
		change(changed.Capability)
		digest, err := KernelPlanDigest(b, [32]byte{1}, changed)
		if err != nil || digest == original {
			t.Fatal("distinct input not bound", err)
		}
	}
	// Neither bytes nor caller-owned plans become invocation authority.
	registry, _ := NewContributorRegistry([]Contributor{&registryContributor{p.Contributors[0]}, &planAuditContributor{registryContributor{p.Contributors[1]}}, &registryContributor{p.Contributors[2]}, &registryContributor{p.Contributors[3]}})
	if admitted, e := registry.admitKernelPlan(b, [32]byte{1}, p); e == nil || admitted != nil {
		t.Fatal("unimplemented participant admitted")
	}
	if _, e := json.Marshal(p.Capability); e == nil {
		t.Fatal("proof metadata serialized")
	}
	if fmt.Sprintf("%#v", *p.Capability) != "postgres.CapabilityPlan(redacted)" {
		t.Fatal("proof metadata formatted")
	}
}

func TestCapabilityPlanRejectsInvalidInputs(t *testing.T) {
	p, _ := capabilityPlanFixture(t)
	b := codecBinding()
	b.OperationID = "identity.identifier.attach"
	b.RecordID = "identifier-a"
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Capability.CapabilityID = "" },
		func(p *CommandPlan) { p.Capability.Purpose = "foreign" },
		func(p *CommandPlan) { p.Capability.ReplayDigest = [32]byte{} },
		func(p *CommandPlan) { p.Capability.ReplayKeyVersion = 0 },
		func(p *CommandPlan) { p.Capability.ProofFingerprint = [32]byte{} },
		func(p *CommandPlan) { p.Capability.ExpiresAt = time.Time{} },
		func(p *CommandPlan) { p.Capability.ExpiresAt = p.Capability.ExpiresAt.Add(time.Nanosecond) },
		func(p *CommandPlan) { p.Capability.ExpiresAt = p.Capability.ExpiresAt.In(time.FixedZone("non-UTC", 0)) },
		func(p *CommandPlan) { p.Capability.ExpiresAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(p *CommandPlan) { p.Capability.MaxUses = 0 },
		func(p *CommandPlan) { p.Capability.MaxUses = 2 },
		func(p *CommandPlan) { p.Lifecycle = nil },
		func(p *CommandPlan) { p.Contributors[3].Version = 2 },
		func(p *CommandPlan) { p.Contributors[3].ContractID = "capability.other" },
		func(p *CommandPlan) { p.Contributors = p.Contributors[:3] },
		func(p *CommandPlan) { p.Capability = nil },
	} {
		changed := p
		cp := *p.Capability
		changed.Capability = &cp
		changed.Contributors = append([]ContributorDescriptor(nil), p.Contributors...)
		change(&changed)
		if _, err := KernelPlanDigest(b, [32]byte{1}, changed); err == nil {
			t.Fatal("invalid capability input accepted")
		}
	}
	// Creation must reject, not silently omit, a caller-supplied capability.
	c, command, creation := coordinatorFixture(t)
	creation.Capability = p.Capability
	if _, err := c.PrepareCommandPlan(codecBinding(), command, creation); err == nil {
		t.Fatal("unsupported input silently dropped")
	}
}

func TestCapabilityPlanPreservesCommittedByteGoldens(t *testing.T) {
	// Captured from the unmodified 80ea588 encoder, not recomputed by this
	// implementation. Old journal digests must survive this additive profile.
	b := codecBinding()
	wire := queryFrozenPlan(t, b)
	if fmt.Sprintf("%x", sha256.Sum256(wire)) != "b155f09205f71af7f44970ca18d7d50e49f3a6e3e61d77bd2fa67cfc033b460e" {
		t.Fatal("audit-only bytes changed")
	}
	p, err := decodeKernelPlan(b, [32]byte{1}, wire)
	if err != nil {
		t.Fatal(err)
	}
	p.Lifecycle = &LifecyclePlan{EventType: kernelLifecycleEvent(b.OperationID), EventIndex: 11, AfterVersion: 1}
	p.Contributors = append(p.Contributors, ContributorDescriptor{Owner: "outbox/postgres", ContractID: "identity.lifecycle", Version: 1})
	wire, err = encodeKernelPlan(b, [32]byte{1}, p)
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(wire)) != "4fddfd9a29a7ff78596bd99385f0a57bc968231f94033fb54cd4178c2c250c91" {
		t.Fatal("lifecycle bytes changed", err)
	}
}

func FuzzDecodeCapabilityPlan(f *testing.F) {
	_, wire := capabilityPlanFixture(f)
	f.Add(wire)
	f.Add([]byte{0xbf})
	b := codecBinding()
	b.OperationID = "identity.identifier.attach"
	b.RecordID = "identifier-a"
	f.Fuzz(func(t *testing.T, wire []byte) {
		p, err := decodeKernelPlan(b, [32]byte{1}, wire)
		if err != nil {
			if !reflect.DeepEqual(p, CommandPlan{}) {
				t.Fatal("partial capability plan escaped")
			}
			return
		}
		canonical, err := encodeKernelPlan(b, [32]byte{1}, p)
		if err != nil || !bytes.Equal(canonical, wire) || p.Digest != sha256.Sum256(wire) {
			t.Fatal("noncanonical capability plan accepted")
		}
	})
}

func TestCapabilityPlanDecoderRejectsCorruption(t *testing.T) {
	_, wire := capabilityPlanFixture(t)
	b := codecBinding()
	b.OperationID = "identity.identifier.attach"
	b.RecordID = "identifier-a"
	for i := range wire {
		if got, e := decodeKernelPlan(b, [32]byte{1}, wire[:i]); e == nil || !reflect.DeepEqual(got, CommandPlan{}) {
			t.Fatal("truncated plan accepted")
		}
	}
	for _, tc := range []struct {
		key      string
		old, bad []byte
	}{
		{"max_uses", cborUint(1), cborUint(2)},
		{"purpose", cborText(b.OperationID), cborText("other")},
		{"expires_at", cborUint(1800000000), cborUint(^uint64(0))},
		{"replay_key_version", cborUint(1), cborUint(1 << 32)},
		{"capability_id", cborText("proof-a"), cborText("")},
		{"replay_digest", cborBytes([]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}), cborBytes([]byte{3})},
	} {
		changed := bytes.Replace(wire, append(cborText(tc.key), tc.old...), append(cborText(tc.key), tc.bad...), 1)
		if bytes.Equal(changed, wire) {
			t.Fatal("invalid fixture")
		}
		if got, e := decodeKernelPlan(b, [32]byte{1}, changed); e == nil || !reflect.DeepEqual(got, CommandPlan{}) {
			t.Fatal("corrupt capability field accepted", tc.key)
		}
	}
}
