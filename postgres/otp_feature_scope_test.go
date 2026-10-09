package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestOTPConsumptionRejectsAdmissionOnlyInvocation(t *testing.T) {
	_, command, plan := otpAttemptFixture(t, &otpReservationProbe{})
	spec, _ := command.Feature()
	owner := &scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}
	plan.Feature.Contributor = owner.Descriptor()
	frozen := &admittedKernelPlan{binding: spec.Binding, feature: plan.Feature, lifecycle: plan.Lifecycle, otp: cloneOTPPlan(plan.OTP), fingerprint: [32]byte{7}}
	// Current-authentication callbacks share FeatureScope but are not protected
	// effect callbacks, even when the original OTP has already been checked.
	w := Work{state: &workState{ctx: context.Background(), binding: spec.Binding, generation: 3, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, otpCommand: &command, execution: &domainExecution{reservation: &reservationState{plan: frozen}}}}
	if got, err := w.OTPConsumption(owner); err == nil || got != (OTPReservationBinding{}) {
		t.Fatal("admission-only invocation obtained protected consuming scope")
	}
}

// Signin's session effect must distinguish a live, checked consuming reservation
// from projected metadata, non-consuming checks and a returned feature handle.
func TestOTPConsumptionRequiresCheckedFeatureInvocation(t *testing.T) {
	_, command, plan := otpAttemptFixture(t, &otpReservationProbe{})
	spec, _ := command.Feature()
	owner := &scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}
	foreign := &scopeFeatureParticipant{operations: owner.operations}
	plan.Feature.Contributor = owner.Descriptor()
	frozen := &admittedKernelPlan{binding: spec.Binding, feature: plan.Feature, lifecycle: plan.Lifecycle, otp: cloneOTPPlan(plan.OTP), fingerprint: [32]byte{7}}
	w := Work{state: &workState{ctx: context.Background(), binding: spec.Binding, generation: 3, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, otpCommand: &command, execution: &domainExecution{reservation: &reservationState{plan: frozen}}}}
	reader, ok := any(w).(interface {
		OTPConsumption(FeatureExecutionContributor) (OTPReservationBinding, error)
	})
	w.state.featureApplying = true
	if !ok {
		t.Fatal("protected session effect cannot observe checked OTP consumption")
	}
	b, err := reader.OTPConsumption(owner)
	if err != nil || b.Command != spec.Binding || b.Plan != *plan.OTP || b.Generation != 3 || b.PreviousGeneration != 0 || b.Fingerprint != frozen.fingerprint {
		t.Fatal("exact checked consuming scope lost", err)
	}
	b.Plan.ScopeDigest[0]++
	again, err := reader.OTPConsumption(owner)
	if err != nil || again.Plan != *frozen.otp {
		t.Fatal("returned projection aliases frozen authority", err)
	}
	for _, p := range []FeatureExecutionContributor{nil, foreign} {
		if got, err := reader.OTPConsumption(p); err == nil || got != (OTPReservationBinding{}) {
			t.Fatal("foreign feature obtained consuming scope")
		}
	}
	for _, mode := range []string{"unchecked", "check-only", "no-plan", "no-execution", "no-reservation", "no-otp", "different-command", "zero-generation", "zero-fingerprint", "returned", "closed"} {
		t.Run(mode, func(t *testing.T) {
			state := *w.state
			p := *frozen
			p.otp = cloneOTPPlan(frozen.otp)
			execution := *state.execution
			reservation := reservationState{}
			execution.reservation, reservation.plan = &reservation, &p
			state.execution = &execution
			switch mode {
			case "unchecked":
				state.otpCommand = nil
			case "check-only":
				p.otp.Mode = OTPCheck
			case "no-plan":
				reservation.plan = nil
			case "no-execution":
				state.execution = nil
			case "no-reservation":
				execution.reservation = nil
			case "no-otp":
				p.otp = nil
			case "different-command":
				p.binding.CommandID, _ = identity.NewCommandID()
			case "zero-generation":
				state.generation = 0
			case "zero-fingerprint":
				p.fingerprint = [32]byte{}
			case "returned":
				state.featureInvocation = nil
			case "closed":
				state.closed = true
			}
			bad := any(Work{state: &state}).(interface {
				OTPConsumption(FeatureExecutionContributor) (OTPReservationBinding, error)
			})
			if got, err := bad.OTPConsumption(owner); err == nil || got != (OTPReservationBinding{}) {
				t.Fatal("invalid phase disclosed consuming authority")
			}
		})
	}
}
