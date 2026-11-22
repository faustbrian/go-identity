package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"reflect"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func unlinkPlanFixture(t *testing.T) (identity.CommandBinding, CommandPlan) {
	t.Helper()
	_, _, plan := coordinatorFixture(t)
	command := recordUnlink(t, func(s *identity.AccountUnlinkCommand) { s.RevokeProvider = false }, nil)
	spec, _ := command.UnlinkAccount()
	proof := spec.Proof.Payload()
	plan.Contributors = append(plan.Contributors,
		ContributorDescriptor{Owner: "capability/postgres", ContractID: "capability.one-use", Version: 1},
		accountLinkCounterDescriptor(), ContributorDescriptor{Owner: "identity/oauth/postgres", ContractID: "identity.oauth.account-unlink", Version: 1})
	plan.Capability = &CapabilityPlan{CapabilityID: proof.ID, Purpose: "identity.account.unlink", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: spec.Proof.EnvelopeDigest(), ExpiresAt: proof.ExpiresAt, MaxUses: 1}
	plan.CommandCounters = &CommandCounterPlan{PolicyVersion: 3, Fingerprint: [32]byte{4}}
	plan.Lifecycle = &LifecyclePlan{EventType: kernelLifecycleEvent(spec.Binding.OperationID), BeforeVersion: 1, AfterVersion: 2}
	record, err := kernelMutationAudit(context.Background(), spec.Binding, 1, time.Unix(1000, 0).UTC(), "committed")
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits[0].EventType = kernelCommandAudit(spec.Binding.OperationID)
	plan.Audits[0].BindingDigest, err = AuditBindingDigest(spec.Binding, record)
	if err != nil {
		t.Fatal(err)
	}
	plan.Audits = oauthAccountUnlinkAuditPlans(plan.Audits[0])
	return spec.Binding, plan
}

func TestAccountUnlinkPlanRetainsExactOwnersAndHistoricalKernelBytes(t *testing.T) {
	binding, plan := unlinkPlanFixture(t)
	fingerprint := [32]byte{5}
	wire, err := encodeKernelPlan(binding, fingerprint, plan)
	if err != nil {
		t.Fatal("complete counter-bound unlink plan rejected", err)
	}
	decoded, err := decodeKernelPlan(binding, fingerprint, wire)
	plan.Digest = sha256.Sum256(wire)
	if err != nil || !reflect.DeepEqual(decoded, plan) {
		t.Fatal("original unlink declaration lost mandatory participant custody", err)
	}
	base := plan
	base.CommandCounters, base.Contributors, base.Digest = nil, plan.Contributors[:4], [32]byte{}
	base.Audits = plan.Audits[:1]
	bare, err := encodeKernelPlan(binding, fingerprint, base)
	if err != nil {
		t.Fatal(err)
	}
	decodedBase, err := decodeKernelPlan(binding, fingerprint, bare)
	base.Digest = sha256.Sum256(bare)
	if err != nil || !reflect.DeepEqual(decodedBase, base) || bytes.Equal(wire, bare) {
		t.Fatal("closed unlink extension changed historical bare declaration", err)
	}
	wrong := binding
	wrong.OperationID = "identity.account.link-token"
	if _, err := decodeKernelPlan(wrong, fingerprint, wire); err == nil {
		t.Fatal("unlink declaration admitted under link operation")
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.Lifecycle = nil },
		func(p *CommandPlan) { p.CommandCounters.Fingerprint = [32]byte{} },
		func(p *CommandPlan) { p.CommandCounters.PolicyVersion = 0 },
		func(p *CommandPlan) { p.Contributors[5] = accountLinkOwnerDescriptor() },
		func(p *CommandPlan) { p.Contributors[4], p.Contributors[5] = p.Contributors[5], p.Contributors[4] },
		func(p *CommandPlan) { p.Contributors = p.Contributors[:5] },
		func(p *CommandPlan) { p.Contributors = append(p.Contributors, accountLinkOwnerDescriptor()) },
		func(p *CommandPlan) { p.AccountLinkState = p.Capability },
	} {
		candidate := plan
		candidate.Contributors = append([]ContributorDescriptor(nil), plan.Contributors...)
		counter := *plan.CommandCounters
		candidate.CommandCounters = &counter
		mutate(&candidate)
		if _, err := encodeKernelPlan(binding, fingerprint, candidate); err == nil {
			t.Fatal("incomplete or substituted unlink declaration admitted")
		}
	}
	for _, corrupted := range [][]byte{wire[:len(wire)-1], append(bytes.Clone(wire), 0)} {
		if _, err := decodeKernelPlan(binding, fingerprint, corrupted); err == nil {
			t.Fatal("noncanonical unlink history accepted")
		}
	}
}
