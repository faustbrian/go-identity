package postgres

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
)

type outputPreparationParticipant struct{ scopeFeatureParticipant }

func (*outputPreparationParticipant) ValidateFeaturePreparation(identity.Command, CommandPlan) error {
	return nil
}
func (*outputPreparationParticipant) AdmitFeaturePreparation(context.Context, Work, identity.Command) error {
	return nil
}
func (*outputPreparationParticipant) GenerateFeaturePreparation(context.Context, identity.Command, uint64) ([]byte, error) {
	return nil, invalidPreparation()
}
func (*outputPreparationParticipant) RestoreFeaturePreparation(context.Context, identity.Command, uint64, []byte) (identity.Command, CommandPlan, error) {
	return identity.Command{}, CommandPlan{}, invalidPreparation()
}

func preparationOutputFixture(t *testing.T) (Work, *outputPreparationParticipant) {
	t.Helper()
	_, command, declaration := featurePlanFixture(t)
	s, _ := command.Feature()
	owner := &outputPreparationParticipant{scopeFeatureParticipant{operations: []identity.FeatureOperation{s.Operation}}}
	registry, err := NewContributorRegistry([]Contributor{owner})
	if err != nil {
		t.Fatal(err)
	}
	declaration.Feature.Contributor = owner.Descriptor()
	plan := &admittedKernelPlan{registry: registry.state, binding: s.Binding, feature: declaration.Feature}
	c := &Coordinator{registry: registry}
	r := &reservationState{coordinator: c, executionRequest: &claimRequest{}, plan: plan,
		journal:     journalReservation{generation: 2},
		preparation: &retainedFeaturePreparation{ciphertext: bytes.Repeat([]byte{0x71}, 17000), generation: 1}}
	w := Work{state: &workState{ctx: context.Background(), binding: s.Binding, registry: registry.state,
		feature: declaration.Feature, lifecycle: &workLifecycle{plan: *declaration.Lifecycle},
		featureAttempted: true, featureInvocation: owner,
		execution: &domainExecution{coordinator: c, reservation: r}}}
	return w, owner
}

func TestFeaturePreparationOutputOwnsOriginalCiphertext(t *testing.T) {
	w, owner := preparationOutputFixture(t)
	wire, generation, err := w.FeaturePreparationOutput(owner)
	if err != nil || generation != 1 || len(wire) != 17000 || !bytes.Equal(wire, w.state.execution.reservation.preparation.ciphertext) {
		t.Fatal("original large custody/provenance lost", err)
	}
	if generation == w.state.execution.reservation.journal.generation {
		t.Fatal("takeover renewed output provenance")
	}
	wire[0] ^= 1
	fresh, generation, err := w.FeaturePreparationOutput(owner)
	if err != nil || generation != 1 || fresh[0] != 0x71 || w.state.execution.reservation.preparation.ciphertext[0] != 0x71 {
		t.Fatal("returned copy mutated retained custody", err)
	}
	other, otherOwner := preparationOutputFixture(t)
	other.state.execution.reservation.preparation.ciphertext[0] = 0x72
	otherWire, _, err := other.FeaturePreparationOutput(otherOwner)
	if err != nil || otherWire[0] != 0x72 || fresh[0] != 0x71 {
		t.Fatal("independent invocation custody crossed", err)
	}
}

func TestFeaturePreparationOutputDeniesUnownedLifetime(t *testing.T) {
	for name, alter := range map[string]func(Work){
		"before apply": func(w Work) { w.state.featureAttempted = false },
		"returned":     func(w Work) { w.state.featureInvocation = nil },
		"closed":       func(w Work) { w.state.closed = true },
		"failed":       func(w Work) { w.state.failed = errors.New("failed") },
		"cancelled":    func(w Work) { ctx, cancel := context.WithCancel(context.Background()); cancel(); w.state.ctx = ctx },
		"expired": func(w Work) {
			ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			cancel()
			w.state.ctx = ctx
		},
		"admission":           func(w Work) { w.state.execution = nil },
		"ordinary":            func(w Work) { w.state.execution.reservation.executionRequest = nil },
		"missing reservation": func(w Work) { w.state.execution.reservation = nil },
		"missing output":      func(w Work) { w.state.execution.reservation.preparation = nil },
		"empty output":        func(w Work) { w.state.execution.reservation.preparation.ciphertext = nil },
		"oversized output": func(w Work) {
			w.state.execution.reservation.preparation.ciphertext = make([]byte, maximumPreparationCiphertext+1)
		},
		"zero generation":     func(w Work) { w.state.execution.reservation.preparation.generation = 0 },
		"foreign coordinator": func(w Work) { w.state.execution.reservation.coordinator = &Coordinator{} },
		"foreign registry":    func(w Work) { w.state.registry = &contributorRegistryState{} },
		"foreign binding":     func(w Work) { w.state.execution.reservation.plan.binding.RecordID += "other" },
		"missing plan":        func(w Work) { w.state.execution.reservation.plan = nil },
	} {
		t.Run(name, func(t *testing.T) {
			w, owner := preparationOutputFixture(t)
			copyOfWork := w
			alter(w)
			if wire, generation, err := copyOfWork.FeaturePreparationOutput(owner); err == nil || wire != nil || generation != 0 {
				t.Fatal("unowned custody disclosed")
			}
		})
	}
	w, owner := preparationOutputFixture(t)
	for _, participant := range []*outputPreparationParticipant{nil, {scopeFeatureParticipant: owner.scopeFeatureParticipant}} {
		if wire, generation, err := w.FeaturePreparationOutput(participant); err == nil || wire != nil || generation != 0 {
			t.Fatal("foreign descriptor alias disclosed custody")
		}
	}
	if wire, generation, err := (Work{}).FeaturePreparationOutput(owner); err == nil || wire != nil || generation != 0 {
		t.Fatal("zero Work disclosed custody")
	}
}
