package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// FeatureFailureCode is a closed SCIM denial classification retained in the
// existing protected journal result, never arbitrary error text or payload.
// Zero denotes unchanged legacy behavior. A code alone grants no authority.
type FeatureFailureCode uint8

const (
	// FeatureFailureUniqueness retains an original uniqueness conflict (HTTP409).
	FeatureFailureUniqueness FeatureFailureCode = iota + 1
	// FeatureFailurePrecondition retains an original version precondition (HTTP412).
	FeatureFailurePrecondition
	// FeatureFailureConflict retains an original generic resource conflict (HTTP409).
	FeatureFailureConflict
)

func (c FeatureFailureCode) valid() bool {
	return c >= FeatureFailureUniqueness && c <= FeatureFailureConflict
}

// TypedFeatureFailureError reports an acknowledged original SCIM NotCommitted
// terminal denial. Unwrap preserves existing identity.ConflictError handling.
// Code is finite, not a receipt or mutation authority. Constructing/returning
// this error cannot attach detail to a journal; only Work.DenyFeature can stage
// it, followed by known rollback and fenced failure-audit/terminal commit.
type TypedFeatureFailureError struct{ Code FeatureFailureCode }

func (TypedFeatureFailureError) Error() string { return "identity: feature conflict" }
func (TypedFeatureFailureError) Unwrap() error { return identity.ConflictError{} }

func featureFailureError(code FeatureFailureCode) error {
	if code == 0 {
		return nil
	}
	return TypedFeatureFailureError{Code: code}
}

func featureFailureOperation(op identity.FeatureOperation) bool {
	return op == scimUserCreationOperation() || scimUserUpdateSelected(op) || op == scimUserUpdateOperation("identity.scim.user-delete")
}

func validFeatureFailureResult(q claimRequest, r identity.CommandResult, code FeatureFailureCode, class string) bool {
	return code == 0 || code.valid() && class == "conflict" && r.Outcome == identity.CommitOutcomeNotCommitted && q.feature != nil && featureFailureOperation(*q.feature) && r.Binding.ActorKind == authorization.SubjectServiceAccount && r.Feature != nil && r.Feature.Operation == *q.feature
}

// DenyFeature captures a finite denial only during this exact registered SCIM
// participant's synchronous Apply with its original command. It accepts the
// closed SCIM create/replace/PATCH/delete v1 schemas, service actor and scim_user
// target. Copies retain original command custody; reconstructed commands deny.
// The same active invocation may refine an already-poisoned ordinary core CAS
// Conflict, but cannot upgrade cancellation, dependency, authorization or other
// failures. Close owned query rows before calling. Invalid calls retain no
// detail and poison usable Work. Returned/foreign/expired handles deny.
//
// This returns ordinary Conflict immediately and stages no SQL or receipt.
// Detail becomes a TypedFeatureFailureError only after Coordinator.Abort proves
// rollback and commits the fenced failure audit and terminal result. Uncertain
// rollback/commit never discloses a finite result. Work remains serial-use.
func (w Work) DenyFeature(ctx context.Context, p FeatureExecutionContributor, command identity.Command, code FeatureFailureCode) error {
	if w.state == nil || w.state.closed || w.state.ctx == nil {
		return invalidWork()
	}
	reject := func(err error) error { w.state.featureFailure = 0; return w.fail(w.state.ctx, err) }
	if ctx == nil {
		return reject(invalidWork())
	}
	if err := w.state.ctx.Err(); err != nil {
		return reject(err)
	}
	if err := ctx.Err(); err != nil {
		return reject(err)
	}
	if w.state.failed != nil {
		if _, ok := w.state.failed.(identity.ConflictError); !ok {
			return reject(w.state.failed)
		}
	}
	s := w.state
	if !code.valid() || s.rows != nil || !s.featureApplying || !sameParticipant(s.featureInvocation, p) || s.featureApplyCommand == nil || *s.featureApplyCommand != command || s.feature == nil || s.feature.Contributor != scimUserCreationDescriptor() || !featureFailureOperation(s.feature.Operation) || s.subjectType != "scim_user" || s.binding.ActorKind != authorization.SubjectServiceAccount || s.generation == 0 || s.execution == nil || s.execution.coordinator == nil || !s.execution.coordinator.owns(w) {
		return reject(invalidWork())
	}
	spec, ok := command.Feature()
	r := s.execution.reservation
	if !ok || spec.Binding != s.binding || spec.Operation != s.feature.Operation || r.plan == nil || r.plan.binding != s.binding || r.plan.feature == nil || *r.plan.feature != *s.feature || r.plan.fingerprint == ([32]byte{}) || r.journal.generation != s.generation {
		return reject(invalidWork())
	}
	entry, err := s.execution.coordinator.registry.selectFeatureOperation(*s.feature)
	if err != nil || !sameParticipant(entry.contributor, p) || s.featureFailure != 0 && s.featureFailure != code {
		return reject(invalidWork())
	}
	s.featureFailure = code
	return w.fail(ctx, identity.ConflictError{})
}
