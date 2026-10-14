package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type commandCounterProbe struct{}

func (*commandCounterProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}
}
func (*commandCounterProbe) ValidateCommandCounters(identity.Command, CommandCounterPlan) error {
	return nil
}
func (*commandCounterProbe) ReserveCommandCounters(context.Context, CommandCounterWork) (CommandCounterDisposition, error) {
	return CommandCounterAllowed, nil
}
func (*commandCounterProbe) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryNotCommitted, nil
}

func TestCommandCounterPlanFreezesAndRoundTrips(t *testing.T) {
	c, command, p := featurePlanFixture(t)
	// Native preparation needs the complete existing feature phase.
	s, _ := command.Feature()
	phase := &scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}}
	entries := []Contributor{&riskPassiveProbe{registryContributor{c.registry.state.entries[0].descriptor}}, &riskPassiveProbe{registryContributor{c.registry.state.entries[1].descriptor}}, &riskPassiveProbe{registryContributor{c.registry.state.entries[2].descriptor}}, phase, &commandCounterProbe{}}
	r, err := NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	c.registry = r
	p.Feature.Contributor = phase.Descriptor()
	p.Contributors = r.Descriptors()
	p.SubjectType = "session"
	p.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{3}}
	seed, err := securityMutationAudit(context.Background(), s.Binding, 0, 1, time.Now().UTC().Truncate(time.Microsecond), "committed", "session.issue", "session", s.Binding.RecordID, "standard", true)
	if err != nil {
		t.Fatal(err)
	}
	p.Audits[0].RetentionClass = "standard"
	p.Audits[0].BindingDigest, err = FeatureAuditBindingDigest(s.Binding, s.Operation, "session", seed)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := c.PrepareCommandPlan(s.Binding, command, p)
	if err != nil {
		t.Fatal("protected counter plan unavailable", err)
	}
	q, err := prepareClaim(command, [32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := claimFingerprint([32]byte{1}, q.canonical)
	encoded, err := encodeFeaturePlan(s.Binding, fingerprint, prepared)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeFeaturePlan(s.Binding, fingerprint, encoded)
	if err != nil || decoded.CommandCounters == nil || *decoded.CommandCounters != *prepared.CommandCounters {
		t.Fatal("counter plan lost", err)
	}
	p.CommandCounters.PolicyVersion++
	if prepared.CommandCounters.PolicyVersion != 3 {
		t.Fatal("caller plan aliases admitted state")
	}
	if _, err := KernelPlanDigest(s.Binding, fingerprint, prepared); err == nil {
		t.Fatal("kernel silently ignored counter profile")
	}
	for _, change := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CommandCounters.PolicyVersion = 0 },
		func(p *CommandPlan) { p.CommandCounters.Fingerprint = [32]byte{} },
		func(p *CommandPlan) { p.SubjectType = "" },
		func(p *CommandPlan) { p.RiskEvidence = &RiskEvidencePlan{} },
		func(p *CommandPlan) { p.Contributors = p.Contributors[:4] },
	} {
		bad := prepared
		copy := *prepared.CommandCounters
		bad.CommandCounters = &copy
		change(&bad)
		if _, err := c.PrepareCommandPlan(s.Binding, command, bad); err == nil {
			t.Fatal("invalid counter declaration admitted")
		}
	}
	for _, value := range []any{CommandCounterPlan{}, CommandCounterBinding{}, CommandCounterWork{}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("counter serialization allowed")
		}
		if payload, err := value.(interface{ MarshalText() ([]byte, error) }).MarshalText(); err == nil || len(payload) != 0 {
			t.Fatal("counter text serialization allowed")
		}
		if !strings.Contains(fmt.Sprintf("%+v", value), "redacted") {
			t.Fatal("counter diagnostic unredacted")
		}
	}
	if _, err := (RecoveryWork{}).CommandCounterBinding(&commandCounterProbe{}); err == nil {
		t.Fatal("zero recovery supplied charge metadata")
	}
}

func TestKernelPreparationRejectsCommandCounterDeclaration(t *testing.T) {
	c, command, p := coordinatorFixture(t)
	p.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{3}}
	if _, err := c.PrepareCommandPlan(codecBinding(), command, p); err == nil {
		t.Fatal("kernel preparation silently discarded protected counter declaration")
	}
}
