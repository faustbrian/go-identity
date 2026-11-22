package postgres

import (
	"bytes"
	"testing"
	"time"

	"github.com/faustbrian/go-capability/v2"
	identity "github.com/faustbrian/go-identity"
)

func unlinkRestorationFixture(t *testing.T) (*Coordinator, identity.Command, identity.Command, CommandPlan) {
	t.Helper()
	c, original, declaration, _ := unlinkPreparationFixture(t)
	input, _, _ := original.AccountUnlinkPreparationInput()
	issued := recordUnlink(t, func(s *identity.AccountUnlinkCommand) { s.RevokeProvider = false }, func(p *capability.Payload) {
		p.IssuedAt, p.NotBefore, p.ExpiresAt = time.Unix(990, 0), time.Unix(990, 0), time.Unix(1050, 0)
	})
	generated, err := identity.NewAccountUnlinkCounterCommand(issued, input.Counters)
	if err != nil {
		t.Fatal(err)
	}
	spec, _, _ := generated.AccountUnlinkCounterCommand()
	proof := spec.Proof.Payload()
	declaration.Capability = &CapabilityPlan{CapabilityID: proof.ID, Purpose: "identity.account.unlink", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: spec.Proof.EnvelopeDigest(), ExpiresAt: proof.ExpiresAt, MaxUses: 1}
	return c, original, generated, declaration
}

func TestAccountUnlinkRestorationPreservesOriginalIntentAndEarliestAuthority(t *testing.T) {
	c, original, generated, final := unlinkRestorationFixture(t)
	declaration := final
	declaration.Capability = nil
	q, snapshot, err := c.prepareRestoredAccountUnlink(original, generated, declaration, final)
	if err != nil || snapshot.Capability == nil || snapshot.AccountLinkState != nil {
		t.Fatal("exact bounded issued child cannot attach to original unlink", err)
	}
	expected, err := prepareClaim(generated, c.keys.retained[c.keys.current])
	originalClaim, other := prepareClaim(original, c.keys.retained[c.keys.current])
	if err != nil || other != nil || !bytes.Equal(q.canonical, expected.canonical) || bytes.Equal(q.canonical, originalClaim.canonical) || !bytes.Equal(q.safeFields, originalClaim.safeFields) {
		t.Fatal("restoration changed original scope or replaced issued claim")
	}
	for _, change := range []func(*identity.AccountUnlinkPreparationCommand){
		func(s *identity.AccountUnlinkPreparationCommand) { s.Change.ExpectedUserVersion++ },
		func(s *identity.AccountUnlinkPreparationCommand) { s.Counters.Network = "192.0.2.99" },
		func(s *identity.AccountUnlinkPreparationCommand) {
			s.Counters.PreparedAt = s.Counters.PreparedAt.Add(time.Microsecond)
		},
		func(s *identity.AccountUnlinkPreparationCommand) { s.Counters.KeyVersions = []uint32{9} },
		func(s *identity.AccountUnlinkPreparationCommand) {
			s.Primary.Proof.ExpiresAt = time.Unix(1050, 0).Add(-time.Nanosecond)
		},
		func(s *identity.AccountUnlinkPreparationCommand) { s.Primary.Proof.IssuedAt = time.Unix(991, 0) },
	} {
		if _, _, err := c.prepareRestoredAccountUnlink(recordUnlinkPreparation(t, change, 1), generated, declaration, final); err == nil {
			t.Fatal("generated child changed original intent, counters or authority interval")
		}
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CommandCounters.PolicyVersion++ },
		func(p *CommandPlan) { p.Audits[0].RetentionPolicyVersion++ },
		func(p *CommandPlan) { p.Capability.ProofFingerprint[0]++ },
		func(p *CommandPlan) { p.Lifecycle.AfterVersion++ },
		func(p *CommandPlan) { p.Contributors[5] = accountLinkOwnerDescriptor() },
	} {
		candidate := final
		candidate.Audits = append([]AuditPlan(nil), final.Audits...)
		candidate.Contributors = append([]ContributorDescriptor(nil), final.Contributors...)
		capability, counters, lifecycle := *final.Capability, *final.CommandCounters, *final.Lifecycle
		candidate.Capability, candidate.CommandCounters, candidate.Lifecycle = &capability, &counters, &lifecycle
		mutate(&candidate)
		if _, _, err := c.prepareRestoredAccountUnlink(original, generated, declaration, candidate); err == nil {
			t.Fatal("generated output replaced original declaration")
		}
	}
}
