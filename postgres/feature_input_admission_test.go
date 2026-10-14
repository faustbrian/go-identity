package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"testing"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	primitive "github.com/faustbrian/go-password"
)

type featureInputAdmissionProbe struct {
	scopeFeatureParticipant
	calls              int
	retained           Work
	deny, panic, apply bool
}

type signupInputAdmissionProbe struct {
	scopeFeatureParticipant
	calls    int
	retained Work
}

func (*signupInputAdmissionProbe) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/password/postgres", ContractID: "identity.password", Version: 1}
}
func (p *signupInputAdmissionProbe) AdmitFeaturePreparation(_ context.Context, w Work, c identity.Command) error {
	p.calls++
	p.retained = w
	spec, ok := c.PasswordSignupInputFeature()
	if !ok {
		spec, ok = c.PasswordSignupFeature()
	}
	b, _, _, err := w.FeatureScope(p)
	if !ok || err != nil || b != spec.Binding || w.state.featureApplying {
		return invalidWork()
	}
	return nil
}

func TestFeatureInputAdmissionSelectsOpaqueSignupWithoutGenericDowngrade(t *testing.T) {
	for _, input := range []bool{true, false} {
		t.Run(map[bool]string{true: "original-input", false: "generated-verifier"}[input], func(t *testing.T) {
			spec := passwordSignupCodecSpec(true)
			wire := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{25}, 32))
			var command identity.Command
			var err error
			if input {
				secret, e := primitive.NewSecret([]byte("synthetic signup candidate"))
				if e != nil {
					t.Fatal(e)
				}
				defer secret.Destroy()
				command, err = identity.NewFeaturePasswordSignupInputCommand(spec, secret, auth.NewBearerCredential(wire))
			} else {
				command, err = identity.NewFeaturePasswordSignupCommand(spec, "$synthetic$verifier", auth.NewBearerCredential(wire))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := command.Feature(); ok {
				t.Fatal("sealed password became generic metadata")
			}
			probe := &signupInputAdmissionProbe{scopeFeatureParticipant: scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}}
			registry, err := NewContributorRegistry([]Contributor{probe})
			if err != nil {
				t.Fatal(err)
			}
			registration := &FeatureRegistration{Contributor: probe.Descriptor(), Operation: spec.Operation}
			lifecycle := &LifecyclePlan{EventType: "user.created.v1"}
			plan := &admittedKernelPlan{registry: registry.state, binding: spec.Binding, feature: registration, lifecycle: lifecycle}
			work := Work{state: &workState{ctx: context.Background(), registry: registry.state, binding: spec.Binding, feature: registration, lifecycle: &workLifecycle{plan: *lifecycle}}}
			coordinator := &Coordinator{registry: registry}
			if err := coordinator.invokeFeatureInputAdmission(t.Context(), work, command, plan); err != nil || probe.calls != 1 {
				t.Fatal("sealed signup admission rejected", err)
			}
			if _, _, _, err := probe.retained.FeatureScope(probe); err == nil {
				t.Fatal("returned invocation retained scope")
			}
		})
	}
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
