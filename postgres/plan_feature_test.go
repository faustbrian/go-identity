package postgres

import (
	"bytes"
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func featurePlanFixture(t *testing.T) (*Coordinator, identity.Command, CommandPlan) {
	t.Helper()
	c, _, p := coordinatorFixture(t)
	feature := featureRegistryInput()
	entries := []Contributor{c.registry.state.entries[0].contributor, c.registry.state.entries[1].contributor, c.registry.state.entries[2].contributor, feature}
	r, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = r
	s := featureCodecSpec()
	p.Contributors = r.Descriptors()
	p.Feature = &FeatureRegistration{Contributor: feature.descriptor, Operation: feature.operations[0]}
	p.Audits[0].EventType = "session.issue"
	p.Lifecycle.EventType = "session.created.v1"
	return c, featureCodecCommand(t, s), p
}

func TestFeaturePlanPreparationFreezesExactRegisteredSelection(t *testing.T) {
	c, command, p := featurePlanFixture(t)
	s, _ := command.Feature()
	prepared, err := c.PrepareCommandPlan(s.Binding, command, p)
	if err != nil || prepared.Digest == ([32]byte{}) {
		t.Fatal("feature plan preparation", err)
	}
	original := prepared.Digest
	p.Contributors[3].Version++
	p.Feature.Operation.SchemaVersion++
	p.Audits[0].EventType = "changed.action"
	p.Lifecycle.AfterVersion++
	if prepared.Feature.Operation != s.Operation || prepared.Contributors[3].Version != 1 || prepared.Audits[0].EventType != "session.issue" || prepared.Lifecycle.AfterVersion != 1 {
		t.Fatal("caller mutated prepared plan")
	}
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := FeaturePlanDigest(s.Binding, claimFingerprint([32]byte{1}, q.canonical), prepared)
	if err != nil || digest != original {
		t.Fatal("digest owner changed", err)
	}
	if _, err := KernelPlanDigest(s.Binding, [32]byte{1}, prepared); err == nil {
		t.Fatal("feature entered kernel plan")
	}
	reservation, result, err := c.ReserveCommand(context.Background(), s.Binding, command, prepared)
	if err == nil || reservation.state != nil || result != (identity.CommandResult{}) {
		t.Fatal("preparation enabled reservation")
	}
}

func TestFeaturePlanRejectsUnknownSchemasAndIncompletePhases(t *testing.T) {
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Feature = nil },
		func(p *CommandPlan) { p.Feature.Contributor.Version++ },
		func(p *CommandPlan) { p.Feature.Operation.Owner = "identity/password" },
		func(p *CommandPlan) { p.Feature.Operation.RecordRequirement = identity.FeatureRecordOmitted },
		func(p *CommandPlan) { p.Feature.Operation.SchemaVersion++ },
		func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
		func(p *CommandPlan) { p.Lifecycle = nil },
		func(p *CommandPlan) { p.Lifecycle.AfterVersion = 2 },
		func(p *CommandPlan) { p.Audits = nil },
		func(p *CommandPlan) { p.Audits[0].Required = false },
		func(p *CommandPlan) { p.Contributors = p.Contributors[:3] },
		func(p *CommandPlan) { p.Contributors[3] = p.Contributors[0] },
	} {
		c, command, p := featurePlanFixture(t)
		s, _ := command.Feature()
		mutate(&p)
		got, err := c.PrepareCommandPlan(s.Binding, command, p)
		if err == nil || got.Feature != nil || got.Digest != ([32]byte{}) {
			t.Fatal("invalid feature prefix escaped")
		}
	}
	c, command, p := featurePlanFixture(t)
	s, _ := command.Feature()
	s.Binding.ActorID = "foreign"
	if _, err := c.PrepareCommandPlan(s.Binding, command, p); err == nil {
		t.Fatal("foreign binding prepared")
	}
	c, command, p = featurePlanFixture(t)
	s, _ = command.Feature()
	c.registry.state.entries[1].contributor = &registryContributor{p.Contributors[1]}
	if _, err := c.PrepareCommandPlan(s.Binding, command, p); err == nil {
		t.Fatal("missing audit phase accepted")
	}
	c, command, p = featurePlanFixture(t)
	s, _ = command.Feature()
	c.registry.state.entries[2].contributor = &registryContributor{p.Contributors[2]}
	if _, err := c.PrepareCommandPlan(s.Binding, command, p); err == nil {
		t.Fatal("missing lifecycle phase accepted")
	}
}

func TestFeatureReceiptCodecMatchesExactCommandDescriptor(t *testing.T) {
	s := featureCodecSpec()
	q, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	r := identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}}
	encoded, err := encodeJournalResult(q, r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeJournalResult(q, encoded)
	if err != nil || got.Feature == nil || got.Feature.Operation != s.Operation || got.Feature.AfterVersion != 1 {
		t.Fatal("feature receipt changed", err)
	}
	r.Feature.Operation.Owner = "identity/password"
	if _, err := encodeJournalResult(q, r); err == nil {
		t.Fatal("foreign owner receipt encoded")
	}
	tampered := bytes.Replace(encoded, []byte("identity/session"), []byte("identity/password"), 1)
	if _, err := decodeJournalResult(q, tampered); err == nil {
		t.Fatal("foreign owner receipt decoded")
	}
	if _, err := decodeJournalResult(claimRequest{safeFields: q.safeFields}, encoded); err == nil {
		t.Fatal("scope alone fabricated historical descriptor")
	}
}

func TestFeaturePlanDigestConservesEveryDeclaration(t *testing.T) {
	c, command, p := featurePlanFixture(t)
	s, _ := command.Feature()
	prepared, err := c.PrepareCommandPlan(s.Binding, command, p)
	if err != nil {
		t.Fatal(err)
	}
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	fp := claimFingerprint([32]byte{1}, q.canonical)
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Contributors[0], p.Contributors[3] = p.Contributors[3], p.Contributors[0] },
		func(p *CommandPlan) { p.Audits[0].EventType = "session.other" },
		func(p *CommandPlan) { p.Audits[0].EventIndex++ },
		func(p *CommandPlan) { p.Audits[0].BindingDigest[0]++ },
		func(p *CommandPlan) { p.Audits[0].RetentionPolicyVersion++ },
		func(p *CommandPlan) { p.Audits[0].MaxRecordBytes-- },
		func(p *CommandPlan) {
			p.Audits[0].MaxAggregateBytes--
			p.Audits[0].MaxRecordBytes = p.Audits[0].MaxAggregateBytes
		},
		func(p *CommandPlan) { p.Lifecycle.EventType = "session.other.v1" },
		func(p *CommandPlan) { p.Lifecycle.EventIndex++ },
		func(p *CommandPlan) { p.Lifecycle.BeforeVersion = 1; p.Lifecycle.AfterVersion = 2 },
		func(p *CommandPlan) { a := p.Audits[0]; a.EventIndex++; p.Audits = append(p.Audits, a) },
	} {
		_, _, changed := featurePlanFixture(t)
		mutate(&changed)
		got, err := FeaturePlanDigest(s.Binding, fp, changed)
		if err != nil || got == prepared.Digest {
			t.Fatal("valid declaration omitted", err)
		}
	}
	if got, err := FeaturePlanDigest(s.Binding, [32]byte{2}, prepared); err != nil || got == prepared.Digest {
		t.Fatal("fingerprint omitted")
	}
	original := prepared.Digest
	prepared.Digest = [32]byte{99}
	if got, err := FeaturePlanDigest(s.Binding, fp, prepared); err != nil || got != original {
		t.Fatal("self-referential digest")
	}
	if _, err := FeaturePlanDigest(s.Binding, [32]byte{}, prepared); err == nil {
		t.Fatal("zero fingerprint")
	}
	_, kernel, kernelPlan := coordinatorFixture(t)
	ks, _ := kernel.CreateUser()
	kernelPlan.Feature = p.Feature
	if _, err := KernelPlanDigest(ks.Binding, [32]byte{1}, kernelPlan); err == nil {
		t.Fatal("kernel silently omitted feature declaration")
	}
}

func TestFeatureReceiptCodecRejectsNonterminalAndNoncanonical(t *testing.T) {
	s := featureCodecSpec()
	q, err := prepareClaim(featureCodecCommand(t, s), [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	r := identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeNotCommitted, Feature: &identity.FeatureReceipt{Operation: s.Operation}}
	b, err := encodeJournalResult(q, r)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := decodeJournalResult(q, b); err != nil || got.Outcome != identity.CommitOutcomeNotCommitted {
		t.Fatal("feature abort changed")
	}
	for _, bad := range [][]byte{append(append([]byte(nil), b...), ' '), bytes.Replace(b, []byte(`"Feature":`), []byte(`"feature":`), 1), bytes.Replace(b, []byte(`"BeforeVersion":0`), []byte(`"BeforeVersion":0,"BeforeVersion":0`), 1)} {
		if _, err := decodeJournalResult(q, bad); err == nil {
			t.Fatal("noncanonical feature result accepted")
		}
	}
	r.Outcome = identity.CommitOutcomeUnknown
	if _, err := encodeJournalResult(q, r); err == nil {
		t.Fatal("unknown stored as terminal")
	}
}

func FuzzFeatureJournalResult(f *testing.F) {
	s := featureCodecSpec()
	c, err := identity.NewFeatureCommand(s)
	if err != nil {
		f.Fatal(err)
	}
	q, err := prepareClaim(c, [32]byte{1})
	if err != nil {
		f.Fatal(err)
	}
	r := identity.CommandResult{Binding: s.Binding, Outcome: identity.CommitOutcomeCommitted, AuditEventID: "audit-a", Feature: &identity.FeatureReceipt{Operation: s.Operation, AfterVersion: 1}}
	seed, err := encodeJournalResult(q, r)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := decodeJournalResult(q, data)
		if err != nil {
			return
		}
		encoded, err := encodeJournalResult(q, got)
		if err != nil || !bytes.Equal(data, encoded) || got.Feature == nil || got.Feature.Operation != s.Operation {
			t.Fatal("noncanonical/foreign feature receipt decoded")
		}
	})
}
