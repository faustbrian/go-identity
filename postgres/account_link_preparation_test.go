package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

type preparedAccountLinkOwnerProbe struct{ accountLinkOwnerProbe }

func (*preparedAccountLinkOwnerProbe) ValidateAccountLinkPreparation(identity.Command, CommandPlan) error {
	return nil
}
func (*preparedAccountLinkOwnerProbe) AdmitAccountLinkPreparation(context.Context, AccountLinkPreparationWork, identity.Command) error {
	return nil
}
func (*preparedAccountLinkOwnerProbe) GenerateAccountLinkPreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidPreparation()
}
func (*preparedAccountLinkOwnerProbe) RestoreAccountLinkPreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, CapabilityIssuancePlan, error) {
	return identity.Command{}, CommandPlan{}, CapabilityIssuancePlan{}, invalidPreparation()
}

func originalAccountLinkPreparation(t testing.TB, generated identity.Command) identity.Command {
	t.Helper()
	spec, counters, ok := generated.AccountLinkCounterCommand()
	if !ok {
		t.Fatal("counter-enriched generated command required")
	}
	input, err := identity.NewOAuthCallbackInput([]byte("synthetic-original-authorization-code"), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(input.Destroy)
	command, err := identity.NewAccountLinkPreparationCommand(identity.AccountLinkPreparationCommand{Binding: spec.Binding, ProviderID: spec.Change.Account.Provider, ProviderConfigVersion: 1, FlowID: "original-flow", FlowFingerprint: [32]byte{1}, SessionID: spec.SessionID, SessionVersion: spec.SessionVersion, Counters: counters}, input, authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))))
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func preparedAccountLinkPlanFixture(t *testing.T) (*Coordinator, identity.Command, identity.Command, CommandPlan, *preparedAccountLinkOwnerProbe) {
	t.Helper()
	c, generated, plan := accountLinkOwnerPlanFixture(t)
	owner := &preparedAccountLinkOwnerProbe{}
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
	state := *plan.Capability
	state.CapabilityID, state.Purpose, state.ReplayDigest, state.ProofFingerprint = "original-state", "identity.oauth.callback", [32]byte{8}, [32]byte{9}
	plan.AccountLinkState, plan.Capability = &state, nil
	return c, originalAccountLinkPreparation(t, generated), generated, plan, owner
}

func TestAccountLinkPreparationAdmitsOnlyOriginalRootIntentAndCompleteOwner(t *testing.T) {
	c, original, generated, declaration, owner := preparedAccountLinkPlanFixture(t)
	q, admitted, phase, err := c.prepareAccountLinkPreparation(original, declaration)
	if err != nil || admitted == nil || phase != owner || admitted.capability != nil || admitted.accountLinkState == nil || admitted.accountLink == nil || admitted.feature != nil {
		t.Fatal("complete original root preparation rejected", err)
	}
	originalClaim, err := prepareClaim(original, c.keys.retained[c.keys.current])
	if err != nil || !bytes.Equal(q.canonical, originalClaim.canonical) || admitted.fingerprint != claimFingerprint(c.keys.retained[c.keys.current], originalClaim.canonical) {
		t.Fatal("preparation changed immutable original claim", err)
	}
	finalClaim, err := prepareClaim(generated, c.keys.retained[c.keys.current])
	if err != nil || !bytes.Equal(q.safeFields, finalClaim.safeFields) || bytes.Equal(q.canonical, finalClaim.canonical) {
		t.Fatal("preparation substituted generated proof or final scope", err)
	}
	before := *admitted.accountLinkState
	declaration.AccountLinkState.ReplayDigest[0]++
	copy := admitted.snapshot()
	copy.AccountLinkState.ProofFingerprint[0]++
	if *admitted.accountLinkState != before {
		t.Fatal("admitted original state aliases caller metadata")
	}
	for _, command := range []identity.Command{{}, generated} {
		if _, _, _, err := c.prepareAccountLinkPreparation(command, admitted.snapshot()); err == nil {
			t.Fatal("non-original command selected callback preparation")
		}
	}
	spec, _, _ := generated.AccountLinkCounterCommand()
	if _, err := c.PrepareCommandPlan(spec.Binding, generated, admitted.snapshot()); err == nil {
		t.Fatal("original-state profile enabled ordinary account-link reservation")
	}
	for _, mutate := range []func(*CommandPlan){
		func(p *CommandPlan) { p.AccountLinkState = nil },
		func(p *CommandPlan) { p.Capability = &before },
		func(p *CommandPlan) { p.CommandCounters = nil },
		func(p *CommandPlan) { p.Contributors = p.Contributors[:5] },
	} {
		p := admitted.snapshot()
		mutate(&p)
		if _, _, _, err := c.prepareAccountLinkPreparation(original, p); err == nil {
			t.Fatal("incomplete preparation declaration admitted")
		}
	}
	c.registry.state.entries[5].contributor = &accountLinkOwnerProbe{}
	if _, _, _, err := c.prepareAccountLinkPreparation(original, admitted.snapshot()); err == nil {
		t.Fatal("owner without preparation phases admitted")
	}
}

func TestAccountLinkPreparedOwnerBorrowsOnlyItsOriginalInputAndOutput(t *testing.T) {
	c, original, generated, declaration, owner := preparedAccountLinkPlanFixture(t)
	spec, _, _ := generated.AccountLinkCounterCommand()
	proof := spec.Proof.Payload()
	final := declaration
	final.Capability = &CapabilityPlan{CapabilityID: proof.ID, Purpose: "identity.account.link-token", ReplayDigest: [32]byte{3}, ReplayKeyVersion: 1, ProofFingerprint: spec.Proof.EnvelopeDigest(), ExpiresAt: proof.ExpiresAt, MaxUses: 1}
	q, snapshot, err := c.prepareRestoredAccountLink(generated, final)
	if err != nil {
		t.Fatal(err)
	}
	originalClaim, err := prepareClaim(original, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.registry.admitKernelPlan(spec.Binding, claimFingerprint(c.keys.retained[c.keys.current], q.canonical), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	r := &reservationState{coordinator: c, request: originalClaim, executionRequest: &q, plan: p, journal: journalReservation{generation: 2}, preparation: &retainedFeaturePreparation{ciphertext: []byte("synthetic-ciphertext"), generation: 1}}
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: spec.Binding, generation: 2, registry: c.registry.state}}
	w.state.execution = &domainExecution{coordinator: c, reservation: r}
	invocation := &accountLinkInvocation{work: w, participant: owner, command: spec, phase: accountLinkCheck, active: true}
	h := AccountLinkWork{state: invocation}
	input, wire, generation, err := h.Preparation(owner)
	if err != nil || generation != 1 || !bytes.Equal(wire, r.preparation.ciphertext) {
		t.Fatal("original retained preparation unavailable to exact current owner", err)
	}
	inputClaim, err := prepareClaim(input, c.keys.retained[c.keys.current])
	if err != nil || !bytes.Equal(inputClaim.canonical, originalClaim.canonical) {
		t.Fatal("final owner received invented original custody", err)
	}
	wire[0] ^= 1
	_, again, provenance, err := h.Preparation(owner)
	if err != nil || provenance != 1 || !bytes.Equal(again, r.preparation.ciphertext) || bytes.Equal(again, wire) {
		t.Fatal("borrowed output changed retained custody or renewed generation", err)
	}
	if _, wire, generation, err := h.Preparation(&preparedAccountLinkOwnerProbe{}); err == nil || wire != nil || generation != 0 {
		t.Fatal("foreign same-descriptor owner borrowed original preparation")
	}
	invocation.active = false
	if _, wire, generation, err := h.Preparation(owner); err == nil || wire != nil || generation != 0 {
		t.Fatal("returned invocation retained preparation authority")
	}
	if _, wire, generation, err := (AccountLinkWork{}).Preparation(owner); err == nil || wire != nil || generation != 0 {
		t.Fatal("zero handle exposed preparation")
	}
}

func TestAccountLinkPreparationObservationPreservesUnattachedUncertainty(t *testing.T) {
	c, original, _, declaration, _ := preparedAccountLinkPlanFixture(t)
	claim, p, _, err := c.prepareAccountLinkPreparation(original, declaration)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := encodeKernelPlan(p.binding, p.fingerprint, p.snapshot())
	if err != nil {
		t.Fatal(err)
	}
	state, profile := "pending", int16(5)
	now := time.Now().UTC().Truncate(time.Microsecond)
	until := now.Add(time.Second)
	observed := commandObservation{tenant: string(p.binding.TenantID), purpose: p.binding.OperationID, scope: claim.safeFields, fingerprint: p.fingerprint[:], state: &state, until: &until, now: now, preparationProfile: &profile, declaration: wire}
	query := creationRecoveryQuery(p.binding)
	for _, at := range []time.Time{now, until.Add(time.Second)} {
		observed.now = at
		result, err := commandReceipt(query, observed, nil)
		if err != nil || result.Outcome != identity.CommitOutcomeInProgress || result.Binding != p.binding || result.Feature != nil || result.Link != nil || result.Validate() != nil {
			t.Fatal("original root preparation lost its bounded uncertain observation", err)
		}
	}
	for _, mutate := range []func(*commandObservation){
		func(o *commandObservation) { o.declaration = nil },
		func(o *commandObservation) { o.declaration = wire[:len(wire)-1] },
		func(o *commandObservation) { o.fingerprint = bytes.Repeat([]byte{2}, 32) },
		func(o *commandObservation) { o.preparationProfile = nil },
		func(o *commandObservation) { v := int16(4); o.preparationProfile = &v },
		func(o *commandObservation) { v := "committed"; o.state = &v },
		func(o *commandObservation) { o.plan = []byte{} },
	} {
		bad := observed
		mutate(&bad)
		if result, err := commandReceipt(query, bad, nil); err == nil || result.Outcome != identity.CommitOutcomeInvalid {
			t.Fatal("incomplete original preparation disclosed a historical outcome")
		}
	}
}
