package postgres

import (
	identity "github.com/faustbrian/go-identity"
	"reflect"
)

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
