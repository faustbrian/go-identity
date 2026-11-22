package postgres

import (
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func unlinkOwnerPlanFixture(t *testing.T) (*Coordinator, identity.Command, CommandPlan) {
	t.Helper()
	c, _, _ := coordinatorFixture(t)
	_, plan := unlinkPlanFixture(t)
	original := recordUnlink(t, func(s *identity.AccountUnlinkCommand) { s.RevokeProvider = false }, nil)
	command, err := identity.NewAccountUnlinkCounterCommand(original, identity.AccountUnlinkCounterContext{Network: "192.0.2.55", PreparedAt: time.Unix(1000, 0).UTC(), KeyVersions: []uint32{7}})
	if err != nil {
		t.Fatal(err)
	}
	entries := []Contributor{
		&accountLinkDomainProbe{registryContributor{plan.Contributors[0]}},
		&accountLinkAuditProbe{planAuditContributor{registryContributor{plan.Contributors[1]}}},
		&accountLinkLifecycleProbe{planLifecycleContributor{registryContributor{plan.Contributors[2]}}},
		&capabilityExecutionProbe{}, &accountLinkCounterProbe{}, &unlinkOwnerProbe{},
	}
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	plan.Contributors = c.registry.Descriptors()
	return c, command, plan
}

func TestAccountUnlinkOwnerAdmitsOnlyExactProofAndCompleteTypedDeclaration(t *testing.T) {
	c, command, plan := unlinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountUnlinkCounterCommand()
	prepared, err := c.PrepareCommandPlan(spec.Binding, command, plan)
	if err != nil {
		t.Fatal("complete unlink owner cannot prepare canonical declaration", err)
	}
	_, _, admitted, err := c.prepare(spec.Binding, command, prepared)
	if err != nil || !reflect.DeepEqual(admitted.snapshot(), prepared) {
		t.Fatal("unlink declaration lost its typed participant", err)
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Capability.ProofFingerprint[0] ^= 1 },
		func(p *CommandPlan) { p.Capability.ExpiresAt = p.Capability.ExpiresAt.Add(time.Second) },
		func(p *CommandPlan) { p.Capability.CapabilityID = "foreign-proof" },
		func(p *CommandPlan) { p.Lifecycle.BeforeVersion++ },
		func(p *CommandPlan) { p.Lifecycle.AfterVersion++ },
		func(p *CommandPlan) { p.Contributors[5] = accountLinkOwnerDescriptor() },
	} {
		candidate := prepared
		candidate.Contributors = append([]ContributorDescriptor(nil), prepared.Contributors...)
		proof, lifecycle := *prepared.Capability, *prepared.Lifecycle
		candidate.Capability, candidate.Lifecycle = &proof, &lifecycle
		mutate(&candidate)
		if _, err := c.PrepareCommandPlan(spec.Binding, command, candidate); err == nil {
			t.Fatal("substituted unlink proof or participant admitted")
		}
	}
	original, err := identity.NewAccountUnlinkCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PrepareCommandPlan(spec.Binding, original, plan); err == nil {
		t.Fatal("bare unlink omitted protected counter custody")
	}
}
