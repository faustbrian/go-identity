package postgres

import (
	"context"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type featureCommandIdentityReader interface {
	FeatureCommandIdentity(FeatureExecutionContributor) (identity.CommandBinding, [32]byte, uint64, error)
}

func TestFeatureCommandIdentityRequiresExactProtectedInvocation(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	owner := &scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}
	foreign := &scopeFeatureParticipant{operations: owner.operations}
	plan.Feature.Contributor = owner.Descriptor()
	frozen := &admittedKernelPlan{binding: spec.Binding, feature: plan.Feature, lifecycle: plan.Lifecycle, fingerprint: [32]byte{7}}
	reservation := &reservationState{plan: frozen, journal: journalReservation{generation: 3}}
	w := Work{state: &workState{ctx: context.Background(), binding: spec.Binding, generation: 3, feature: plan.Feature, lifecycle: &workLifecycle{plan: *plan.Lifecycle}, featureInvocation: owner, featureApplying: true, execution: &domainExecution{reservation: reservation}}}
	reader, ok := any(w).(featureCommandIdentityReader)
	if !ok {
		t.Fatal("native feature cannot derive original command fingerprint/generation")
	}
	b, fingerprint, generation, err := reader.FeatureCommandIdentity(owner)
	if err != nil || b != spec.Binding || fingerprint != frozen.fingerprint || generation != 3 {
		t.Fatal("original command identity lost", err)
	}
	fingerprint[0]++
	_, again, _, err := reader.FeatureCommandIdentity(owner)
	if err != nil || again != frozen.fingerprint {
		t.Fatal("returned identity aliases frozen authority", err)
	}
	for _, p := range []FeatureExecutionContributor{nil, foreign} {
		if b, f, g, err := reader.FeatureCommandIdentity(p); err == nil || b != (identity.CommandBinding{}) || f != ([32]byte{}) || g != 0 {
			t.Fatal("foreign participant acquired command identity")
		}
	}
	for _, mode := range []string{"admission-only", "returned", "closed", "cancelled", "expired", "zero-generation", "wrong-generation", "zero-fingerprint", "foreign-binding", "foreign-feature", "no-execution", "no-reservation", "no-plan"} {
		t.Run(mode, func(t *testing.T) {
			state := *w.state
			p := *frozen
			r := reservationState{plan: frozen, journal: reservation.journal}
			e := *state.execution
			r.plan, e.reservation, state.execution = &p, &r, &e
			switch mode {
			case "admission-only":
				state.featureApplying = false
			case "returned":
				state.featureInvocation = nil
			case "closed":
				state.closed = true
			case "cancelled":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				state.ctx = ctx
			case "expired":
				ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
				defer cancel()
				state.ctx = ctx
			case "zero-generation":
				state.generation = 0
			case "wrong-generation":
				r.journal.generation++
			case "zero-fingerprint":
				p.fingerprint = [32]byte{}
			case "foreign-binding":
				p.binding.CommandID, _ = identity.NewCommandID()
			case "foreign-feature":
				f := *p.feature
				f.Operation.SchemaID = "foreign"
				p.feature = &f
			case "no-execution":
				state.execution = nil
			case "no-reservation":
				e.reservation = nil
			case "no-plan":
				r.plan = nil
			}
			bad := any(Work{state: &state}).(featureCommandIdentityReader)
			if b, f, g, err := bad.FeatureCommandIdentity(owner); err == nil || b != (identity.CommandBinding{}) || f != ([32]byte{}) || g != 0 {
				t.Fatal("invalid phase disclosed original ownership")
			}
		})
	}
}
