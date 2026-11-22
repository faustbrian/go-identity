package postgres

import (
	"bytes"
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

func preparedUnlinkInvocationFixture(t *testing.T) (*Coordinator, Work, identity.Command, *preparedUnlinkOwnerProbe) {
	t.Helper()
	c, original, generated, final := unlinkRestorationFixture(t)
	declaration := final
	declaration.Capability = nil
	q, snapshot, err := c.prepareRestoredAccountUnlink(original, generated, declaration, final)
	if err != nil {
		t.Fatal(err)
	}
	originalClaim, err := prepareClaim(original, c.keys.retained[c.keys.current])
	if err != nil {
		t.Fatal(err)
	}
	spec, _, _ := generated.AccountUnlinkCounterCommand()
	fp := claimFingerprint(c.keys.retained[c.keys.current], q.canonical)
	p, err := c.registry.admitKernelPlan(spec.Binding, fp, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	t.Cleanup(cancel)
	r := &reservationState{coordinator: c, request: originalClaim, executionRequest: &q, plan: p,
		journal: journalReservation{generation: 3}, preparation: &retainedFeaturePreparation{ciphertext: []byte("synthetic-retained-ciphertext"), generation: 2}}
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: spec.Binding, generation: 3, registry: c.registry.state}}
	w.state.execution = &domainExecution{coordinator: c, reservation: r}
	return c, w, generated, p.accountUnlink.contributor.(*preparedUnlinkOwnerProbe)
}

func TestAccountUnlinkPhaseAdmitsOnlyActualPreparedExecutionClaim(t *testing.T) {
	c, w, generated, owner := preparedUnlinkInvocationFixture(t)
	owner.check = func(h AccountUnlinkWork) error {
		_, _, err := h.Command(owner)
		return err
	}
	if _, err := c.runAccountUnlinkPhase(w.state.ctx, w, generated, accountUnlinkCheck, nil); err != nil {
		t.Fatal("authenticated generated unlink compared against original password metadata instead of issued intent", err)
	}
}

func TestAccountUnlinkPreparedWorkRetainsOriginalPasswordProvenance(t *testing.T) {
	type preparedWork interface {
		Preparation(AccountUnlinkPreparationContributor) (identity.Command, []byte, uint64, error)
	}
	_, w, generated, owner := preparedUnlinkInvocationFixture(t)
	spec, _, _ := generated.AccountUnlinkCounterCommand()
	invocation := &accountUnlinkInvocation{work: w, participant: owner, command: spec, phase: accountUnlinkCheck, active: true}
	h, ok := any(AccountUnlinkWork{state: invocation}).(preparedWork)
	if !ok {
		t.Fatal("actual unlink owner cannot borrow original password-proof preparation")
	}
	original, wire, generation, err := h.Preparation(owner)
	if err != nil || generation != 2 || !bytes.Equal(wire, w.state.execution.reservation.preparation.ciphertext) {
		t.Fatal("original encrypted output or non-renewed generation lost", err)
	}
	input, _, ok := original.AccountUnlinkPreparationInput()
	if !ok || input.Primary.Proof.ID != "original-password-proof" || input.Binding != spec.Binding {
		t.Fatal("native owner received substitute proof/session provenance")
	}
	wire[0]++
	_, retained, provenance, err := h.Preparation(owner)
	if err != nil || provenance != generation || bytes.Equal(wire, retained) || !bytes.Equal(retained, w.state.execution.reservation.preparation.ciphertext) {
		t.Fatal("borrowed output mutated original ciphertext or generation", err)
	}
	if _, wire, generation, err := h.Preparation(&preparedUnlinkOwnerProbe{}); err == nil || wire != nil || generation != 0 || w.usable() == nil {
		t.Fatal("foreign same-descriptor owner borrowed original password provenance")
	}
	invocation.active = false
	if _, wire, generation, err := h.Preparation(owner); err == nil || wire != nil || generation != 0 {
		t.Fatal("returned invocation retained original authority")
	}
}
