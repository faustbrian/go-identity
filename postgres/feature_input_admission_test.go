package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type featureInputAdmissionProbe struct {
	scopeFeatureParticipant
	calls              int
	retained           Work
	deny, panic, apply bool
}

func (p *featureInputAdmissionProbe) AdmitFeaturePreparation(ctx context.Context, w Work, c identity.Command) error {
	p.calls++
	p.retained = w
	spec, _ := c.Feature()
	b, _, _, err := w.FeatureScope(p)
	if err != nil || b != spec.Binding || w.state.featureApplying || w.state.featurePreparationCommand == nil || *w.state.featurePreparationCommand != c {
		return invalidWork()
	}
	if p.panic {
		panic("private admission detail")
	}
	if p.apply {
		return w.RequireFeatureCommand(ctx, p, c)
	}
	if p.deny {
		return identity.ForbiddenError{}
	}
	return nil
}

func TestFeatureInputAdmissionScopesExactOwnerWithoutApplyCustody(t *testing.T) {
	_, command, plan := featurePlanFixture(t)
	spec, _ := command.Feature()
	for _, behavior := range []string{"allow", "deny", "panic", "apply"} {
		t.Run(behavior, func(t *testing.T) {
			p := &featureInputAdmissionProbe{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}, deny: behavior == "deny", panic: behavior == "panic", apply: behavior == "apply"}
			registry, err := NewContributorRegistry([]Contributor{p})
			if err != nil {
				t.Fatal(err)
			}
			registration := &FeatureRegistration{Contributor: p.Descriptor(), Operation: spec.Operation}
			admitted := &admittedKernelPlan{registry: registry.state, binding: spec.Binding, feature: registration, lifecycle: plan.Lifecycle}
			w := Work{state: &workState{ctx: context.Background(), registry: registry.state, binding: spec.Binding, feature: registration, lifecycle: &workLifecycle{plan: *plan.Lifecycle}}}
			c := &Coordinator{registry: registry}
			err = c.invokeFeatureInputAdmission(context.Background(), w, command, admitted)
			if (err == nil) != (behavior == "allow") || p.calls != 1 {
				t.Fatal("native admission was omitted or acquired apply authority", err)
			}
			if w.state.featureInvocation != nil || w.state.featurePreparationCommand != nil || w.state.featurePreparationPlan != nil {
				t.Fatal("returned admission retained invocation custody")
			}
			if _, _, _, err := p.retained.FeatureScope(p); err == nil {
				t.Fatal("retained admission work regained owner scope")
			}
			if behavior != "allow" && w.state.failed == nil {
				t.Fatal("failed native admission did not poison its transaction")
			}
		})
	}
}
