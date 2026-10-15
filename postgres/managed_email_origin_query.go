package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// QueryManagedEmailPreparation reads original encrypted output for a committed
// native email-management request. The caller and q name current disclosure
// authority for verification-confirm or change-confirm, not the historical
// human's session. q.CommandID is the authenticated issuance origin; tenant,
// user and RecordID must be its signed scope. The exact registered preparation
// owner must first authenticate the issued proof, then authenticate/decrypt the
// returned output and authorize its original email intent. This read itself
// grants no mailbox ownership, credential use or current session authority.
//
// Only self-user native-v1 verification-send and change-request origins match
// their respective confirmation actions. Missing, retired, foreign and
// noncommitted history denies. Incomplete/corrupt output fails unavailable.
// Generic original-actor recovery/query rules are unchanged. No preparation,
// generation, renewal, takeover, mutation or credential consumption occurs.
// Output is an owned sensitive copy; clear after use and never log/serialize it.
// The pool remains borrowed; immutable composition supports concurrent reads.
// MaximumDuration and earlier caller deadlines bound policy and primary IO.
// Failures return zero binding, bytes and generation with redacted typed errors.
func (c *Coordinator) QueryManagedEmailPreparation(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, feature FeatureRegistration, owner FeaturePreparationContributor) (binding identity.CommandBinding, wire []byte, generation uint64, err error) {
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || c.registry == nil || c.commandRead == nil || c.queryPolicy == nil || !validCommandQueryPolicy(*c.queryPolicy) || c.maximumDuration <= 0 || c.maximumDuration > time.Minute || !managedEmailOriginOperation(feature, q.OperationID) || q.AnonymousFlowID != "" || q.LinkMode != 0 {
		return binding, nil, 0, invalidPreparation()
	}
	entry, e := c.registry.selectFeatureOperation(feature)
	if e != nil || !sameParticipant(entry.contributor, owner) {
		return binding, nil, 0, invalidPreparation()
	}
	if _, e := identity.ParseCommandID(string(q.CommandID)); e != nil {
		return binding, nil, 0, invalidPreparation()
	}
	for _, value := range []string{string(q.TenantID), string(q.UserID), string(q.ActorID), string(q.ActorKind), q.RecordID} {
		if !queryScopeText(value) {
			return binding, nil, 0, invalidPreparation()
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = readFailure(ctx, ctx.Err())
		}
		if errors.Is(err, identity.ErrUserAbsent) {
			err = identity.ForbiddenError{}
		}
		if err != nil {
			clear(wire)
			binding, wire, generation = identity.CommandBinding{}, nil, 0
		}
	}()
	allowed, policyErr := c.authorizeCommandQuery(ctx, q, caller)
	observed, observeErr := c.commandRead(ctx, q.CommandID)
	if ctx.Err() != nil {
		return binding, nil, 0, readFailure(ctx, ctx.Err())
	}
	if policyErr != nil {
		return binding, nil, 0, identity.UnavailableError{}
	}
	if !allowed {
		return binding, nil, 0, identity.ForbiddenError{}
	}
	if observeErr != nil {
		return binding, nil, 0, readFailure(ctx, observeErr)
	}
	b, op, decodeErr := decodeObservedScope(observed.scope)
	if decodeErr != nil {
		return binding, nil, 0, identity.UnavailableError{}
	}
	// The selected request owner may also register its closed resend schema.
	// Select only that observed original operation, never caller-provided scope.
	if op != nil && *op == emailResendOperation() && feature.Operation == (identity.FeatureOperation{Owner: "identity/email", OperationID: "identity.email.verification-send", SchemaID: "identity.email.verification-send.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) {
		feature.Operation = *op
		selected, e := c.registry.selectFeatureOperation(feature)
		if e != nil || !sameParticipant(selected.contributor, owner) {
			return binding, nil, 0, identity.ForbiddenError{}
		}
	}
	if op == nil || *op != feature.Operation || b.CommandID != q.CommandID || b.TenantID != q.TenantID || b.UserID != q.UserID || b.RecordID != q.RecordID || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) || b.LinkMode != 0 {
		return binding, nil, 0, identity.ForbiddenError{}
	}
	original := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
	receipt, receiptErr := commandReceipt(original, observed, nil)
	if receiptErr != nil {
		return binding, nil, 0, receiptErr
	}
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		return binding, nil, 0, identity.ForbiddenError{}
	}
	wire, generation, err = c.readFeaturePreparation(ctx, original, b, feature, owner, observed)
	return b, wire, generation, err
}

func managedEmailOriginOperation(feature FeatureRegistration, confirm string) bool {
	var request string
	switch confirm {
	case "identity.email.verification-confirm":
		request = "identity.email.verification-send"
	case "identity.email.change-confirm":
		request = "identity.email.change-request"
	default:
		return false
	}
	return feature.Contributor == (ContributorDescriptor{Owner: "identity/email/postgres", ContractID: "identity.email", Version: 1}) && (feature.Operation == (identity.FeatureOperation{Owner: "identity/email", OperationID: request, SchemaID: request + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}) || request == "identity.email.verification-send" && feature.Operation == emailResendOperation())
}
