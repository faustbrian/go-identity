package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestCapabilityReleaseAuthorityCannotBeConstructed(t *testing.T) {
	var w CapabilityReleaseWork
	if _, err := w.Binding(nil); err == nil {
		t.Fatal("zero release binding admitted")
	}
	if _, err := w.Exec(context.Background(), "SELECT 1"); err == nil {
		t.Fatal("zero release SQL admitted")
	}
	if rows, err := w.Query(context.Background(), "SELECT 1"); err == nil || rows != nil {
		t.Fatal("zero release rows admitted")
	}
	if _, err := w.DatabaseTime(context.Background()); err == nil {
		t.Fatal("zero release clock admitted")
	}
	var evidence RecoveryWork
	if _, err := evidence.CapabilityBinding(nil); err == nil {
		t.Fatal("zero recovery binding admitted")
	}
	if fmt.Sprintf("%+v", w) != "postgres.CapabilityReleaseWork(redacted)" {
		t.Fatal("release metadata leaked")
	}
	if _, err := json.Marshal(w); err == nil {
		t.Fatal("release authority serialized")
	}
}

func TestCapabilityReleaseProvenanceDoesNotWidenReservation(t *testing.T) {
	for _, proof := range []capabilityReleaseProof{capabilityReleaseRecovery, capabilityReleaseRollback} {
		p := &capabilityExecutionProbe{}
		c, work := capabilityDomainFixture(t, p)
		previous := uint64(2)
		if proof == capabilityReleaseRollback {
			previous = 3
		}
		state := &capabilityReservationState{coordinator: c, work: work, plan: work.state.execution.reservation.plan, previousGeneration: previous, active: true, contributor: p, releaseProof: proof}
		handle := CapabilityReleaseWork{state: state}
		binding, err := handle.Binding(p)
		if err != nil || binding.Generation != 3 || binding.PreviousGeneration != previous {
			t.Fatal("exact release custody rejected", err)
		}
		if _, err := handle.Binding(&capabilityExecutionProbe{}); err == nil {
			t.Fatal("foreign owner admitted")
		}
		reservation := CapabilityReservationWork{state: state}
		if _, err := reservation.Binding(p); err == nil {
			t.Fatal("release widened reservation authority")
		}
		if _, err := reservation.Exec(context.Background(), "SELECT 1"); err == nil {
			t.Fatal("release widened reservation SQL")
		}
		state.previousGeneration++
		if _, err := handle.Binding(p); err == nil {
			t.Fatal("wrong previous generation admitted")
		}
		state.previousGeneration = previous
		state.releaseProof = 0
		if _, err := handle.Binding(p); err == nil {
			t.Fatal("unproven release admitted")
		}
		state.releaseProof = proof
		state.active = false
		if _, err := handle.Binding(p); err == nil {
			t.Fatal("expired invocation admitted")
		}
	}
}
