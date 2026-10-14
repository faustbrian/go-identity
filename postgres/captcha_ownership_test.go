package postgres

import (
	"context"
	"testing"
)

func TestCaptchaDomainOwnershipRequiresExactDeclaredInvocation(t *testing.T) {
	c, command, plan := captchaReservationFixture(t)
	spec, _ := command.Feature()
	p, err := c.PrepareCommandPlan(spec.Binding, command, plan)
	if err != nil {
		t.Fatal(err)
	}
	_, _, admitted, err := c.prepare(spec.Binding, command, p)
	if err != nil {
		t.Fatal(err)
	}
	participant := c.registry.state.entries[3].contributor.(CaptchaReplayContributor)
	w := Work{state: &workState{ctx: context.Background(), binding: spec.Binding, generation: 2, registry: c.registry.state, feature: p.Feature, lifecycle: &workLifecycle{plan: *p.Lifecycle}, featureInvocation: participant,
		execution: &domainExecution{coordinator: c, reservation: &reservationState{coordinator: c, plan: admitted, journal: journalReservation{generation: 2}}}}}
	owner, err := w.CaptchaReplayOwnership(participant)
	if err != nil || owner.Fingerprint != admitted.fingerprint || owner.Generation != 2 {
		t.Fatal("original current owner lost", err)
	}
	if _, err := w.CaptchaReplayOwnership(&captchaReservationProbe{}); err == nil {
		t.Fatal("descriptor alias admitted")
	}
	for _, change := range []func(*workState){
		func(s *workState) { s.featureInvocation = nil },
		func(s *workState) { s.generation = 0 },
		func(s *workState) { s.closed = true },
		func(s *workState) { s.execution = nil },
	} {
		copy := *w.state
		change(&copy)
		if _, err := (Work{state: &copy}).CaptchaReplayOwnership(participant); err == nil {
			t.Fatal("invalid or returned invocation admitted")
		}
	}
	w.state.execution.reservation.journal.previousGeneration = 1
	recovery := RecoveryWork{state: &recoveryWorkState{work: w, active: true, plan: admitted, entry: registeredContributor{contributor: participant, descriptor: participant.Descriptor()}}}
	recovered, err := recovery.CaptchaReplayOwnership(participant)
	if err != nil || recovered.Fingerprint != owner.Fingerprint || recovered.Generation != owner.Generation || recovered.PreviousGeneration != 1 {
		t.Fatal("recovery lost original generation", err)
	}
	w.state.execution.reservation.journal.previousGeneration = 0
	if _, err := recovery.CaptchaReplayOwnership(participant); err == nil {
		t.Fatal("missing previous participant owner admitted")
	}
	w.state.execution.reservation.journal.previousGeneration = 1
	if _, err := recovery.CaptchaReplayOwnership(&captchaReservationProbe{}); err == nil {
		t.Fatal("foreign recovery principal admitted")
	}
	recovery.state.active = false
	if _, err := recovery.CaptchaReplayOwnership(participant); err == nil {
		t.Fatal("returned recovery invocation admitted")
	}
	if _, err := (RecoveryWork{}).CaptchaReplayOwnership(participant); err == nil {
		t.Fatal("zero recovery admitted")
	}
	if _, err := owner.MarshalJSON(); err == nil {
		t.Fatal("native ownership serialized")
	}
	if _, err := owner.MarshalText(); err == nil {
		t.Fatal("native ownership serialized as text")
	}
	admitted.captchaReplay = false
	if _, err := w.CaptchaReplayOwnership(participant); err == nil {
		t.Fatal("undeclared replay phase admitted")
	}
	if _, err := (Work{}).CaptchaReplayOwnership(participant); err == nil {
		t.Fatal("zero Work admitted")
	}
}
