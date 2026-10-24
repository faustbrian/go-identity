package postgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RequestKeyRecoveryContributor optionally restores original correlation from
// its existing authenticated request-key ciphertext. The exact registered
// native owner must authenticate every RequestKeyPreparationBinding field and
// its immutable configuration, decode the complete original CommandBinding and
// return no binding on failure. RestoreRequestKey is a bounded, concurrency-safe
// decoder outside SQL: no input preparation, authority refresh, execution,
// counters, entropy, delivery, external callbacks or mutation may occur. Borrowed
// ciphertext is valid only during the call and must not be retained or logged.
type RequestKeyRecoveryContributor interface {
	RequestKeyPreparationContributor
	RestoreRequestKey(context.Context, RequestKeyPreparationBinding, []byte) (identity.CommandBinding, error)
}

// RecoverPreparedFeatureCommand observes/reconciles the exact original command
// using current query authorization, the existing immutable prepared-request
// mapping and its registered owner's authenticated native decoder. Neither an
// initiating key nor caller-constructed binding is accepted as outcome evidence.
// The complete decoded original scope must match q. The owner must additionally
// enforce its current session/domain disclosure policy before returning results.
//
// An actual mapping whose claim is absent yields original correlation and
// UnknownCommitError, never NotCommitted, a receipt of effects or permission to
// execute again. A concurrent original may still create its journal. Existing
// journals use the ordinary sole recovery owner, historical scope checks and
// generation fence. Missing/foreign/corrupt mappings or denied current policy
// disclose no correlation. Generic QueryCommand/RecoverFeatureCommand preserve
// their uniform missing/denied contract. Earlier deadlines win; decoder errors
// and panics are redacted, resources remain borrowed, and no goroutine starts.
func (c *Coordinator) RecoverPreparedFeatureCommand(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, feature FeatureRegistration, owner RequestKeyRecoveryContributor) (identity.CommandResult, error) {
	if c == nil || ctx == nil || c.maximumDuration <= 0 || c.maximumDuration > time.Minute {
		return identity.CommandResult{}, coordinatorError()
	}
	ctx, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	input, wire, err := c.QueryRequestPreparation(ctx, q, caller, feature, owner)
	defer clear(wire)
	if err != nil {
		return identity.CommandResult{}, err
	}
	original, err := restoreRequestKey(ctx, owner, input, wire)
	if err != nil {
		return identity.CommandResult{}, err
	}
	absent := featureOutcome(original, &feature.Operation, identity.CommitOutcomeUnknown, 0)
	if original.CommandID != input.Admission.CommandID || original.TenantID != input.Scope.TenantID || original.ActorID != input.Scope.ActorID || original.ActorKind != input.Scope.ActorKind || original.OperationID != input.Scope.RouteID || original.SchemaID != feature.Operation.SchemaID || original.SchemaVersion != feature.Operation.SchemaVersion || absent.Validate() != nil || !requestRecoveryScope(q, original) {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	check := func(observed commandObservation) error {
		binding, operation, err := decodeObservedScope(observed.scope)
		if err != nil || operation == nil || *operation != feature.Operation || binding != original {
			return identity.ForbiddenError{}
		}
		return nil
	}
	r, err := c.queryCommandReceiptMapped(ctx, q, caller, check, &absent)
	return c.reconcileFeatureReceipt(ctx, q, r, err, check)
}

func requestRecoveryScope(q identity.RecoveryQuery, b identity.CommandBinding) bool {
	return q.CommandID == b.CommandID && q.TenantID == b.TenantID && q.UserID == b.UserID && q.AnonymousFlowID == b.AnonymousFlowID && q.ActorID == b.ActorID && q.ActorKind == b.ActorKind && q.OperationID == b.OperationID && q.RecordID == b.RecordID && q.LinkMode == b.LinkMode
}

func restoreRequestKey(ctx context.Context, owner RequestKeyRecoveryContributor, input RequestKeyPreparationBinding, wire []byte) (binding identity.CommandBinding, err error) {
	defer func() {
		if recover() != nil {
			binding, err = identity.CommandBinding{}, identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			binding, err = identity.CommandBinding{}, readFailure(ctx, ctx.Err())
		}
	}()
	if ctx.Err() != nil {
		return binding, readFailure(ctx, ctx.Err())
	}
	binding, err = owner.RestoreRequestKey(ctx, input, wire)
	if err != nil {
		return identity.CommandBinding{}, identity.UnavailableError{}
	}
	return binding, nil
}
