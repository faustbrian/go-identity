package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

func TestPreparedAccountLinkExecutesAttachedCommandWithoutReplacingOriginalClaim(t *testing.T) {
	for _, mode := range []string{"attached", "missing-state", "missing-output", "missing-generation", "missing-generated-claim", "wrong-original-variant", "changed-generated-command"} {
		t.Run(mode, func(t *testing.T) {
			c, work, generated, owner := accountLinkInvocationFixture(t)
			spec, counters, _ := generated.AccountLinkCounterCommand()
			callback, err := identity.NewOAuthCallbackInput([]byte("synthetic-original-authorization-code"), base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), identity.OAuthCallbackLimits{MaxCodeBytes: 4096, StateBytes: 32})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(callback.Destroy)
			original, err := identity.NewAccountLinkPreparationCommand(identity.AccountLinkPreparationCommand{Binding: spec.Binding, ProviderID: spec.Change.Account.Provider, ProviderConfigVersion: 1, FlowID: "original-flow", FlowFingerprint: [32]byte{1}, SessionID: spec.SessionID, SessionVersion: spec.SessionVersion, Counters: counters}, callback, authentication.NewBearerCredential(base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))))
			if err != nil {
				t.Fatal(err)
			}
			originalClaim, err := prepareClaim(original, c.keys.retained[c.keys.current])
			if err != nil {
				t.Fatal(err)
			}
			r := work.state.execution.reservation
			generatedClaim := r.request
			r.request, r.executionRequest = originalClaim, &generatedClaim
			r.preparation = &retainedFeaturePreparation{ciphertext: []byte("synthetic-authenticated-output"), generation: 1}
			r.journal.generation, work.state.generation = 2, 2
			state := *r.plan.capability
			state.Purpose, state.CapabilityID, state.ProofFingerprint = "identity.oauth.callback", "original-state", [32]byte{9}
			r.plan.accountLinkState = &state
			originalBytes := bytes.Clone(r.request.canonical)
			switch mode {
			case "missing-state":
				r.plan.accountLinkState = nil
			case "missing-output":
				r.preparation = nil
			case "missing-generation":
				r.preparation.generation = 0
			case "missing-generated-claim":
				r.executionRequest = nil
			case "wrong-original-variant":
				r.request = generatedClaim
			case "changed-generated-command":
				counters.Network = "192.0.2.200"
				base, err := identity.NewAccountLinkCommand(spec)
				if err != nil {
					t.Fatal(err)
				}
				generated, err = identity.NewAccountLinkCounterCommand(base, counters)
				if err != nil {
					t.Fatal(err)
				}
			}
			called := false
			owner.check = func(h AccountLinkWork) error {
				called = true
				actual, final, err := h.Command(owner)
				if err != nil || final || actual.Binding != spec.Binding || actual.Proof.EnvelopeDigest() != spec.Proof.EnvelopeDigest() {
					t.Fatal("native owner did not receive the exact attached signed command", err)
				}
				return nil
			}
			err = c.runAccountLinkPhase(work.state.ctx, work, generated, accountLinkCheck)
			if mode == "attached" {
				if err != nil || !called || !bytes.Equal(originalBytes, r.request.canonical) || bytes.Equal(r.request.canonical, r.executionRequest.canonical) {
					t.Fatal("attached execution rejected or replaced immutable original intent", err)
				}
			} else if err == nil || called || work.usable() == nil {
				t.Fatal("incomplete or substituted preparation reached native execution")
			}
		})
	}
}

func accountLinkStateExecutionFixture(t *testing.T) (*Coordinator, Work, *capabilityExecutionProbe) {
	t.Helper()
	c, command, plan := accountLinkOwnerPlanFixture(t)
	spec, _, _ := command.AccountLinkCounterCommand()
	_, _, admitted, err := c.prepare(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	state := *admitted.capability
	state.CapabilityID, state.Purpose = "original-oauth-state", "identity.oauth.callback"
	state.ReplayDigest, state.ProofFingerprint = [32]byte{8}, [32]byte{9}
	admitted.accountLinkState = &state
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	t.Cleanup(cancel)
	w := Work{state: &workState{ctx: ctx, cancel: cancel, binding: spec.Binding, generation: 3, registry: c.registry.state}}
	w.state.execution = &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: admitted}}
	return c, w, c.registry.state.entries[3].contributor.(*capabilityExecutionProbe)
}

func TestAccountLinkCapabilityExecutionKeepsStateAndFinalGrantDistinct(t *testing.T) {
	for _, finalize := range []bool{false, true} {
		c, work, participant := accountLinkStateExecutionFixture(t)
		var seen []CapabilityPlan
		var retained []*capabilityExecutionState
		participant.inspect = func(state *capabilityExecutionState) {
			binding, err := state.binding(participant, finalize)
			if err != nil {
				t.Fatal(err)
			}
			seen = append(seen, binding.Plan)
			retained = append(retained, state)
		}
		if err := c.runCapabilityExecution(work.state.ctx, work, finalize); err != nil {
			t.Fatal(err)
		}
		plan := work.state.execution.reservation.plan
		if len(seen) != 2 || !reflect.DeepEqual(seen[0], *plan.accountLinkState) || !reflect.DeepEqual(seen[1], *plan.capability) {
			t.Fatal("execution omitted or substituted one of the original-state and generated-link inputs")
		}
		for _, state := range retained {
			if _, err := state.binding(participant, finalize); err == nil {
				t.Fatal("retained input invocation remained usable")
			}
		}
	}
}

func TestAccountLinkStateInputNeverFallsBackToFinalGrant(t *testing.T) {
	c, work, participant := accountLinkStateExecutionFixture(t)
	p := work.state.execution.reservation.plan
	state := &capabilityReservationState{coordinator: c, work: work, plan: p, active: true, contributor: participant, inputSlot: capabilityOriginalAccountLinkState}
	binding, err := (CapabilityReservationWork{state: state}).Binding(participant)
	if err != nil || binding.Plan.Purpose != "identity.oauth.callback" {
		t.Fatal("original state not selected", err)
	}
	p.accountLinkState = nil
	if _, err := (CapabilityReservationWork{state: state}).Binding(participant); err == nil {
		t.Fatal("missing state fell back to generated link grant")
	}
	state.inputSlot = capabilityInputSlot(255)
	if _, err := (CapabilityReservationWork{state: state}).Binding(participant); err == nil {
		t.Fatal("unknown input selector admitted")
	}
	state.inputSlot = capabilityPrimaryInput
	if _, err := (CapabilityReservationWork{state: state}).Binding(participant); err != nil {
		t.Fatal("historical primary input changed", err)
	}
	p.binding.LinkMode = identity.AccountLinkAdministrative
	state.inputSlot = capabilityOriginalAccountLinkState
	if _, err := (CapabilityReservationWork{state: state}).Binding(participant); err == nil {
		t.Fatal("original state widened to administrative profile")
	}
}

func TestAccountLinkCapabilityReleaseCoversBothOriginalInputs(t *testing.T) {
	for _, proof := range []capabilityReleaseProof{capabilityReleaseRecovery, capabilityReleaseRollback} {
		c, work, participant := accountLinkStateExecutionFixture(t)
		var seen []CapabilityPlan
		var retained []CapabilityReleaseWork
		participant.inspectRelease = func(w CapabilityReleaseWork) error {
			b, err := w.Binding(participant)
			if err != nil {
				return err
			}
			seen = append(seen, b.Plan)
			retained = append(retained, w)
			return nil
		}
		previous := uint64(2)
		if proof == capabilityReleaseRollback {
			previous = 3
		}
		plan := work.state.execution.reservation.plan
		if err := c.releaseCapabilityWithProof(work.state.ctx, work, plan, previous, proof); err != nil {
			t.Fatal(err)
		}
		if len(seen) != 2 || !reflect.DeepEqual(seen[0], *plan.accountLinkState) || !reflect.DeepEqual(seen[1], *plan.capability) {
			t.Fatal("noncommit release omitted or substituted an input")
		}
		for _, w := range retained {
			if _, err := w.Binding(participant); err == nil {
				t.Fatal("retained release authority remained live")
			}
		}
	}
}

func TestAccountLinkCapabilityRecoveryNeedsBothInputsNegative(t *testing.T) {
	for _, stateStatus := range []RecoveryStatus{RecoveryNotCommitted, RecoveryCommitted, RecoveryUnknown} {
		_, work, participant := accountLinkStateExecutionFixture(t)
		plan := work.state.execution.reservation.plan
		work.state.execution.reservation.journal = journalReservation{generation: 3, previousGeneration: 2}
		var seen []CapabilityPlan
		var retained []RecoveryWork
		participant.inspectRecovery = func(w RecoveryWork) (RecoveryStatus, error) {
			b, err := w.CapabilityBinding(participant)
			if err != nil {
				return RecoveryUnknown, err
			}
			seen = append(seen, b.Plan)
			retained = append(retained, w)
			if b.Plan.Purpose == "identity.oauth.callback" {
				return stateStatus, nil
			}
			return RecoveryNotCommitted, nil
		}
		owner := &recoveryWorkState{work: work, entry: plan.contributors[3], plan: plan, active: true}
		status, err := invokeRecovery(work.state.ctx, participant, RecoveryWork{state: owner})
		owner.active = false
		if err != nil || len(seen) == 0 || !reflect.DeepEqual(seen[0], *plan.accountLinkState) {
			t.Fatal("recovery did not inspect original state", err)
		}
		if stateStatus == RecoveryNotCommitted {
			if status != RecoveryNotCommitted || len(seen) != 2 || !reflect.DeepEqual(seen[1], *plan.capability) {
				t.Fatal("both negative inputs not required")
			}
		} else if status == RecoveryNotCommitted {
			t.Fatal("original state uncertainty or use became proof of noncommit")
		}
		for _, w := range retained {
			if _, err := w.CapabilityBinding(participant); err == nil {
				t.Fatal("retained recovery invocation stayed live")
			}
		}
	}
}
