package postgres

import (
	"context"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

type scopeFeatureParticipant struct{ operations []identity.FeatureOperation }

func (*scopeFeatureParticipant) Descriptor() ContributorDescriptor {
	return ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}
}
func (p *scopeFeatureParticipant) FeatureOperations() []identity.FeatureOperation {
	return p.operations
}
func (*scopeFeatureParticipant) ValidateFeatureCommand(identity.Command, CommandPlan) error {
	return nil
}
func (*scopeFeatureParticipant) ApplyFeature(context.Context, Work, identity.Command) (identity.FeatureReceipt, error) {
	return identity.FeatureReceipt{}, nil
}
func (*scopeFeatureParticipant) RecoverParticipant(context.Context, RecoveryWork) (RecoveryStatus, error) {
	return RecoveryUnknown, nil
}

func TestFeatureScopeRequiresExactActiveInvocation(t *testing.T) {
	_, command, p := featurePlanFixture(t)
	spec, _ := command.Feature()
	native := &scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}
	foreign := &scopeFeatureParticipant{operations: []identity.FeatureOperation{spec.Operation}}
	p.Feature.Contributor = native.Descriptor()
	w := Work{state: &workState{ctx: context.Background(), binding: spec.Binding, feature: p.Feature, lifecycle: &workLifecycle{plan: *p.Lifecycle}}}
	if _, _, _, err := w.FeatureScope(native); err == nil {
		t.Fatal("non-invocation scope admitted")
	}
	w.state.featureInvocation = native
	b, op, transition, err := w.FeatureScope(native)
	if err != nil || b != spec.Binding || op != *p.Feature || transition != *p.Lifecycle {
		t.Fatal("exact invocation scope lost", err)
	}
	if _, _, _, err := w.FeatureScope(foreign); err == nil {
		t.Fatal("descriptor alias admitted")
	}
	if _, _, _, err := w.FeatureScope(nil); err == nil {
		t.Fatal("nil participant admitted")
	}
	w.state.featureInvocation = nil
	if _, _, _, err := w.FeatureScope(native); err == nil {
		t.Fatal("returned invocation still admitted")
	}
	if _, _, _, err := (Work{}).FeatureScope(native); err == nil {
		t.Fatal("zero Work")
	}
	r := RecoveryWork{state: &recoveryWorkState{work: w, entry: registeredContributor{contributor: native, descriptor: native.Descriptor()}, plan: &admittedKernelPlan{binding: spec.Binding, feature: p.Feature, lifecycle: p.Lifecycle}, active: true}}
	b, op, transition, err = r.FeatureScope(native)
	if err != nil || b != spec.Binding || op != *p.Feature || transition != *p.Lifecycle {
		t.Fatal("recovery exact scope lost", err)
	}
	if _, _, _, err := r.FeatureScope(foreign); err == nil {
		t.Fatal("foreign recovery admitted")
	}
	r.state.active = false
	if _, _, _, err := r.FeatureScope(native); err == nil {
		t.Fatal("expired recovery admitted")
	}
}
