package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

func anonymousUpgradePlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	b, p := emailVerificationPlanFixture(t)
	b.OperationID, b.SchemaID = "identity.anonymous.upgrade", "identity.anonymous.upgrade.native-v1"
	b.RecordID = "guest-source"
	b.ActorKind, b.ActorID = authorization.SubjectUser, identity.ActorID(b.UserID)
	p.Feature.Operation = identity.FeatureOperation{Owner: "identity/anonymous", OperationID: b.OperationID, SchemaID: b.SchemaID, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	p.Feature.Contributor = ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
	p.Contributors[3] = p.Feature.Contributor
	p.SubjectType = "anonymous"
	p.Audits[0].EventType = "identity.anonymous.upgrade"
	p.Lifecycle = &LifecyclePlan{EventType: "anonymous.upgraded.v1", BeforeVersion: 1, AfterVersion: 2}
	p.Capability.Purpose = "identity.anonymous.upgrade"
	return b, p
}

// Declaration/history proof only. Actual target credentials, guest possession,
// capability verification and SQL effects require the native consumer.
func TestAnonymousUpgradePlanPreservesDistinctTargetAndOneUseProof(t *testing.T) {
	b, p := anonymousUpgradePlanFixture(t)
	fp := [32]byte{1}
	wire, err := encodeFeaturePlan(b, fp, p)
	if err != nil {
		t.Fatal("closed anonymous upgrade unavailable", err)
	}
	got, err := decodeFeaturePlan(b, fp, wire)
	if err != nil || got.Capability == nil || *got.Capability != *p.Capability || got.Digest != sha256.Sum256(wire) || got.Feature == nil || *got.Feature != *p.Feature {
		t.Fatal("original upgrade declaration lost", err)
	}
	again, err := encodeFeaturePlan(b, fp, got)
	if err != nil || !bytes.Equal(again, wire) {
		t.Fatal("upgrade history not canonical", err)
	}
	for n := range wire {
		if _, err := decodeFeaturePlan(b, fp, wire[:n]); err == nil {
			t.Fatal("truncated upgrade accepted", n)
		}
	}
	for _, mutate := range []func(*identity.CommandBinding){
		func(b *identity.CommandBinding) { b.RecordID = string(b.UserID) },
		func(b *identity.CommandBinding) { b.ActorID = identity.ActorID(b.RecordID) },
		func(b *identity.CommandBinding) { b.TenantID = "other-tenant" },
		func(b *identity.CommandBinding) { b.UserID, b.ActorID = "other-target", "other-target" },
	} {
		other := b
		mutate(&other)
		if _, err := decodeFeaturePlan(other, fp, wire); err == nil {
			t.Fatal("foreign guest/target/tenant history accepted")
		}
	}
}

func TestAnonymousUpgradePlanRejectsOpenOrUnprotectedDeclarations(t *testing.T) {
	for _, mutate := range []func(*identity.CommandBinding, *CommandPlan){
		func(b *identity.CommandBinding, _ *CommandPlan) { b.RecordID = string(b.UserID) },
		func(b *identity.CommandBinding, _ *CommandPlan) { b.ActorID = "guest-source" },
		func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Capability = nil
			p.Contributors = p.Contributors[:len(p.Contributors)-1]
		},
		func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Capability.Purpose = "identity.organization.invitation.accept"
		},
		func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.MaxUses = 2 },
		func(_ *identity.CommandBinding, p *CommandPlan) { p.Capability.ProofFingerprint = [32]byte{} },
		func(_ *identity.CommandBinding, p *CommandPlan) {
			p.CommandCounters = nil
			p.Contributors = append(p.Contributors[:4], p.Contributors[5:]...)
		},
		func(_ *identity.CommandBinding, p *CommandPlan) { p.SubjectType = "user" },
		func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].RetentionClass = "standard" },
		func(_ *identity.CommandBinding, p *CommandPlan) { p.Audits[0].EventType = "identity.anonymous.delete" },
		func(_ *identity.CommandBinding, p *CommandPlan) { p.Lifecycle.EventType = "anonymous.deleted.v1" },
		func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Lifecycle.BeforeVersion, p.Lifecycle.AfterVersion = 0, 1
		},
		func(_ *identity.CommandBinding, p *CommandPlan) { p.Feature.Operation.SchemaVersion++ },
		func(_ *identity.CommandBinding, p *CommandPlan) {
			p.Feature.Contributor.ContractID = "identity.other"
			p.Contributors[3] = p.Feature.Contributor
		},
	} {
		b, p := anonymousUpgradePlanFixture(t)
		mutate(&b, &p)
		if _, err := encodeFeaturePlan(b, [32]byte{1}, p); err == nil {
			t.Fatal("open upgrade declaration admitted")
		}
	}
}

type anonymousUpgradeProbe struct {
	scopeFeatureParticipant
	expected identity.Command
	proof    CapabilityPlan
}

func (*anonymousUpgradeProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
}
func (p *anonymousUpgradeProbe) ValidateAnonymousUpgrade(c identity.Command, proof CapabilityPlan) error {
	if c != p.expected || proof != p.proof {
		return invalidPlan()
	}
	return nil
}
func (*anonymousUpgradeProbe) CheckFeatureCommit(context.Context, Work, identity.Command) error {
	return invalidWork()
}

type untypedAnonymousUpgradeProbe struct{ scopeFeatureParticipant }

func (*untypedAnonymousUpgradeProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}
}

func TestAnonymousUpgradeAdmissionRequiresExactTypedNativeOwner(t *testing.T) {
	b, p := anonymousUpgradePlanFixture(t)
	c, _, _ := coordinatorFixture(t)
	command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation, Fields: []identity.FeatureField{{Name: "anonymous.source", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: b.RecordID}}}})
	owner := &anonymousUpgradeProbe{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}, expected: command, proof: *p.Capability}
	audit := &riskPassiveProbe{registryContributor{p.Contributors[1]}}
	outbox := &riskPassiveProbe{registryContributor{p.Contributors[2]}}
	entries := []Contributor{&Repository{}, audit, outbox, owner, &magicLinkPreparationCounter{}, &capabilityExecutionProbe{}}
	var err error
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	p.Contributors = c.registry.Descriptors()
	seed, err := securityMutationAudit(t.Context(), b, 1, 2, time.Now().UTC().Truncate(time.Microsecond), "committed", p.Audits[0].EventType, p.SubjectType, b.RecordID, "protected", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(b, p.Feature.Operation, p.SubjectType, seed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrepareCommandPlan(b, command, p); err != nil {
		t.Fatal("typed original upgrade cannot prepare", err)
	}
	changed := p
	proof := *p.Capability
	proof.ProofFingerprint[0]++
	changed.Capability = &proof
	if _, err := c.PrepareCommandPlan(b, command, changed); err == nil {
		t.Fatal("original proof validation skipped")
	}
	entries[3] = &untypedAnonymousUpgradeProbe{scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}}
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrepareCommandPlan(b, command, p); err == nil {
		t.Fatal("untyped upgrade owner admitted")
	}
}

func TestAnonymousUpgradeConsumptionRequiresExactProtectedInvocation(t *testing.T) {
	for _, mode := range []string{"current", "not-consumed", "finalized", "returned", "commit", "foreign", "closed", "wrong-operation", "missing-proof", "wrong-purpose", "other-generation"} {
		t.Run(mode, func(t *testing.T) {
			b, p := anonymousUpgradePlanFixture(t)
			command := featureCodecCommand(t, identity.FeatureCommandSpec{Binding: b, Operation: p.Feature.Operation})
			owner := &anonymousUpgradeProbe{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{p.Feature.Operation}}, expected: command, proof: *p.Capability}
			plan := &admittedKernelPlan{binding: b, feature: p.Feature, lifecycle: p.Lifecycle, fingerprint: [32]byte{7}, capability: p.Capability}
			r := &reservationState{plan: plan, journal: journalReservation{generation: 1}}
			w := Work{state: &workState{ctx: context.Background(), binding: b, generation: 1, feature: p.Feature, subjectType: "anonymous", lifecycle: &workLifecycle{plan: *p.Lifecycle}, featureInvocation: owner, featureApplying: true, featureApplyCommand: &command, anonymousUpgradeConsumed: true, execution: &domainExecution{reservation: r}}}
			candidate := owner
			switch mode {
			case "not-consumed":
				w.state.anonymousUpgradeConsumed = false
			case "finalized":
				w.state.anonymousUpgradeFinalized = true
			case "returned":
				w.state.featureInvocation = nil
			case "commit":
				w.state.featureApplying = false
			case "foreign":
				candidate = &anonymousUpgradeProbe{}
			case "closed":
				w.state.closed = true
			case "wrong-operation":
				w.state.feature.Operation = anonymousDisposalOperation()
			case "missing-proof":
				plan.capability = nil
			case "wrong-purpose":
				plan.capability.Purpose = "identity.magic-link.consume"
			case "other-generation":
				r.journal.generation++
			}
			got, err := w.AnonymousUpgradeConsumption(candidate)
			if mode != "current" {
				if err == nil || got != (CapabilityReservationBinding{}) {
					t.Fatal("foreign phase acquired upgrade proof")
				}
				return
			}
			if err != nil || got.Command != b || got.Generation != 1 || got.Plan != owner.proof {
				t.Fatal("original upgrade custody lost", err)
			}
			got.Plan.ProofFingerprint[0]++
			if plan.capability.ProofFingerprint != owner.proof.ProofFingerprint {
				t.Fatal("returned declaration aliases original")
			}
		})
	}
	if _, err := (Work{}).AnonymousUpgradeConsumption(&anonymousUpgradeProbe{}); err == nil {
		t.Fatal("zero work acquired proof")
	}
}

func FuzzAnonymousUpgradeConsumptionProfile(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0xa5})
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 65536 {
			return
		}
		b, p := anonymousUpgradePlanFixture(t)
		wire, err := encodeFeaturePlan(b, [32]byte{1}, p)
		if err != nil {
			t.Fatal(err)
		}
		for _, candidate := range [][]byte{wire, input} {
			got, err := decodeFeaturePlan(b, [32]byte{1}, candidate)
			if err != nil {
				continue
			}
			canonical, err := encodeFeaturePlan(b, [32]byte{1}, got)
			if err != nil || !bytes.Equal(candidate, canonical) || got.Capability == nil || got.Capability.Purpose != "identity.anonymous.upgrade" || got.Capability.MaxUses != 1 {
				t.Fatal("foreign or noncanonical upgrade history admitted")
			}
		}
	})
}
