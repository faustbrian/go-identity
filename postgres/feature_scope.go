package postgres

import (
	"context"
	identity "github.com/faustbrian/go-identity"
	"reflect"
)

// RequireFeatureCommand admits only the unchanged command supplied to this
// exact registered participant's synchronous Apply invocation. Ordinary copies
// retain custody; reconstructed commands do not, even with identical fields.
// This bounded local guard performs no IO, callback or fingerprint renewal.
// It does not authenticate credentials or authorize effects. Nil/cancelled
// contexts and foreign, admission-only or returned invocations deny. Rejection
// poisons usable Work so ignoring the error cannot commit earlier effects.
func (w Work) RequireFeatureCommand(ctx context.Context, p FeatureExecutionContributor, command identity.Command) error {
	if err := w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	if _, _, _, err := w.FeatureCommandIdentity(p); err != nil || w.state.featureApplyCommand == nil || *w.state.featureApplyCommand != command {
		return w.fail(ctx, invalidWork())
	}
	return nil
}

// FeatureScope lets a native adapter verify that this exact comparable instance
// is the coordinator's currently invoked feature participant. It returns owned
// frozen scope/schema/version declarations, not policy or proof admission.
// Zero, foreign, closed, expired and post-invocation handles fail. Descriptor
// equality alone is insufficient. No contributor methods, IO or callbacks run.
// This guard does not authorize raw SQL, closure or retaining Work; trusted
// adapters remain responsible for their owned schema and complete validation.
func (w Work) FeatureScope(p FeatureExecutionContributor) (identity.CommandBinding, FeatureRegistration, LifecyclePlan, error) {
	if w.usable() != nil || w.state.feature == nil || w.state.lifecycle == nil || !sameParticipant(w.state.featureInvocation, p) {
		return identity.CommandBinding{}, FeatureRegistration{}, LifecyclePlan{}, invalidWork()
	}
	return w.state.binding, *w.state.feature, w.state.lifecycle.plan, nil
}

// FeatureCommandIdentity returns the original frozen command binding, keyed
// fingerprint and reservation generation during this exact participant's Apply
// invocation. Admission-only, foreign, expired and returned handles deny without
// IO. The owned copies correlate native transactional effects; they are neither
// authentication proof nor a renewable validity lease. Do not log this tuple.
func (w Work) FeatureCommandIdentity(p FeatureExecutionContributor) (identity.CommandBinding, [32]byte, uint64, error) {
	b, feature, _, err := w.FeatureScope(p)
	if err != nil || !w.state.featureApplying || w.state.generation == 0 || w.state.execution == nil || w.state.execution.reservation == nil {
		return identity.CommandBinding{}, [32]byte{}, 0, invalidWork()
	}
	r := w.state.execution.reservation
	plan := r.plan
	if plan == nil || plan.binding != b || plan.feature == nil || *plan.feature != feature || plan.fingerprint == ([32]byte{}) || r.journal.generation != w.state.generation {
		return identity.CommandBinding{}, [32]byte{}, 0, invalidWork()
	}
	return b, plan.fingerprint, w.state.generation, nil
}

// FeatureScope verifies the exact native participant during its recovery-only
// invocation and returns its original frozen transition. It cannot reconstruct
// success from current state or grant mutation/transaction ownership. Nil,
// noncomparable or foreign instances and expired invocations fail without IO.
func (w RecoveryWork) FeatureScope(p FeatureExecutionContributor) (identity.CommandBinding, FeatureRegistration, LifecyclePlan, error) {
	if w.usable() != nil || w.state.plan.feature == nil || w.state.plan.lifecycle == nil || w.state.entry.descriptor != w.state.plan.feature.Contributor || !sameParticipant(w.state.entry.contributor, p) {
		return identity.CommandBinding{}, FeatureRegistration{}, LifecyclePlan{}, invalidWork()
	}
	return w.state.plan.binding, *w.state.plan.feature, *w.state.plan.lifecycle, nil
}

func sameParticipant(a, b Contributor) bool {
	if a == nil || b == nil {
		return false
	}
	// Reject noncomparable implementations rather than panicking on an interface
	// comparison or accepting a compile-time descriptor as instance authority.
	av, bv := reflect.ValueOf(a), reflect.ValueOf(b)
	return av.Comparable() && bv.Comparable() && !nilQueryDependency(a) && !nilQueryDependency(b) && a == b
}
