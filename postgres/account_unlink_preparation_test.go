package postgres

import (
	"bytes"
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type preparedUnlinkOwnerProbe struct{ unlinkOwnerProbe }

func (*preparedUnlinkOwnerProbe) ValidateAccountUnlinkPreparation(identity.Command, CommandPlan) error {
	return nil
}
func (*preparedUnlinkOwnerProbe) AdmitAccountUnlinkPreparation(context.Context, AccountUnlinkPreparationWork, identity.Command) error {
	return nil
}
func (*preparedUnlinkOwnerProbe) GenerateAccountUnlinkPreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidPreparation()
}
func (*preparedUnlinkOwnerProbe) RestoreAccountUnlinkPreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, CapabilityIssuancePlan, error) {
	return identity.Command{}, CommandPlan{}, CapabilityIssuancePlan{}, invalidPreparation()
}

func unlinkPreparationFixture(t *testing.T) (*Coordinator, identity.Command, CommandPlan, *preparedUnlinkOwnerProbe) {
	t.Helper()
	c, _, declaration := unlinkOwnerPlanFixture(t)
	owner := &preparedUnlinkOwnerProbe{}
	entries := make([]Contributor, len(c.registry.state.entries))
	for i := range entries {
		entries[i] = c.registry.state.entries[i].contributor
	}
	entries[5] = owner
	var err error
	c.registry, err = NewContributorRegistry(entries)
	if err != nil {
		t.Fatal(err)
	}
	declaration.Capability = nil
	return c, recordUnlinkPreparation(t, nil, 1), declaration, owner
}

func TestAccountUnlinkPreparationAdmitsOnlyOriginalIntentWithoutExecutionAuthority(t *testing.T) {
	c, original, declaration, owner := unlinkPreparationFixture(t)
	q, admitted, phase, err := c.prepareAccountUnlinkPreparation(original, declaration)
	if err != nil || admitted == nil || phase != owner || admitted.capability != nil || admitted.accountUnlink == nil || admitted.accountLink != nil || admitted.feature != nil {
		t.Fatal("complete original unlink preparation rejected", err)
	}
	expected, err := prepareClaim(original, c.keys.retained[c.keys.current])
	if err != nil || !bytes.Equal(q.canonical, expected.canonical) || admitted.fingerprint != claimFingerprint(c.keys.retained[c.keys.current], q.canonical) {
		t.Fatal("preparation replaced original password/session claim", err)
	}
	if _, err := c.registry.admitKernelPlan(admitted.binding, admitted.fingerprint, admitted.snapshot()); err == nil {
		t.Fatal("grant-free declaration admitted as executable unlink")
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.CommandCounters = nil },
		func(p *CommandPlan) { p.Lifecycle.BeforeVersion++ },
		func(p *CommandPlan) { p.Lifecycle.AfterVersion++ },
		func(p *CommandPlan) { p.Contributors[5] = accountLinkOwnerDescriptor() },
		func(p *CommandPlan) { p.Contributors = p.Contributors[:5] },
		func(p *CommandPlan) { p.Capability = &CapabilityPlan{} },
	} {
		candidate := admitted.snapshot()
		mutate(&candidate)
		if _, _, _, err := c.prepareAccountUnlinkPreparation(original, candidate); err == nil {
			t.Fatal("substituted unlink preparation admitted")
		}
	}
	for _, invalid := range []identity.Command{{}, recordUnlink(t, nil, nil), recordUnlinkPreparation(t, func(s *identity.AccountUnlinkPreparationCommand) { s.RevokeProvider = true }, 1)} {
		if _, _, _, err := c.prepareAccountUnlinkPreparation(invalid, admitted.snapshot()); err == nil {
			t.Fatal("unsupported or issued intent entered original preparation")
		}
	}
	c.registry.state.entries[5].contributor = &unlinkOwnerProbe{}
	if _, _, _, err := c.prepareAccountUnlinkPreparation(original, admitted.snapshot()); err == nil {
		t.Fatal("execution-only owner supplied original preparation")
	}
}

func TestAccountUnlinkPreparationDeclarationRoundTripAndTruncation(t *testing.T) {
	c, original, declaration, _ := unlinkPreparationFixture(t)
	_, admitted, _, err := c.prepareAccountUnlinkPreparation(original, declaration)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeKernelPlan(admitted.binding, admitted.fingerprint, admitted.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeKernelPlan(admitted.binding, admitted.fingerprint, wire)
	if err != nil || decoded.Capability != nil || len(decoded.Contributors) != 6 || decoded.Contributors[5] != accountUnlinkOwnerDescriptor() {
		t.Fatal("original unlink preparation lost its closed ownership", err)
	}
	for i := range wire {
		if _, err := decodeKernelPlan(admitted.binding, admitted.fingerprint, wire[:i]); err == nil {
			t.Fatal("truncated original declaration admitted", i)
		}
	}
	for _, binding := range []identity.CommandBinding{recordBinding("identity.account.link-token", "identity-account", "account-a"), recordBinding("identity.account.unlink", "identity-account", "foreign-account")} {
		if _, err := decodeKernelPlan(binding, admitted.fingerprint, wire); err == nil {
			t.Fatal("original declaration rebound to foreign operation or account")
		}
	}
}

func TestAccountUnlinkPreparationObservationRetainsOriginalDeclaration(t *testing.T) {
	c, original, declaration, _ := unlinkPreparationFixture(t)
	_, admitted, _, err := c.prepareAccountUnlinkPreparation(original, declaration)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeKernelPlan(admitted.binding, admitted.fingerprint, admitted.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"pending", "aborted"} {
		profile := int16(6)
		observed := commandObservation{fingerprint: bytes.Clone(admitted.fingerprint[:]), state: &state, preparationProfile: &profile, declaration: wire}
		plan, preparation, err := observedCommandPlan(admitted.binding, nil, observed)
		if err != nil || !preparation || plan.Capability != nil || plan.AccountLinkState != nil || plan.CommandCounters == nil || plan.Lifecycle == nil || len(plan.Contributors) != 6 || plan.Contributors[5] != accountUnlinkOwnerDescriptor() || *plan.Lifecycle != *admitted.lifecycle {
			t.Fatal("original unlink observation lost immutable preparation scope", state, err)
		}
		for _, mutate := range []func(*commandObservation){
			func(o *commandObservation) { o.preparationProfile = nil },
			func(o *commandObservation) { wrong := int16(5); o.preparationProfile = &wrong },
			func(o *commandObservation) { wrong := "committed"; o.state = &wrong },
			func(o *commandObservation) { o.declaration = wire[:len(wire)-1] },
			func(o *commandObservation) { o.fingerprint[0] ^= 1 },
		} {
			invalid := observed
			invalid.fingerprint = bytes.Clone(observed.fingerprint)
			mutate(&invalid)
			if _, _, err := observedCommandPlan(admitted.binding, nil, invalid); err == nil {
				t.Fatal("substituted unlink preparation observation admitted")
			}
		}
	}
}
