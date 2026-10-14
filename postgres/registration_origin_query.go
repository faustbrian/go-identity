package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// QueryRegistrationPreparation returns original encrypted signup input to its
// exact registered native owner for a currently authorized email confirmation.
// q.CommandID is the original signup command, q.UserID its separately selected
// registration user, and q.OperationID must be identity.email.verification-confirm.
// q.ActorID/ActorKind and caller describe the actual current caller, never the
// historical signup actor. Current CommandQueryPolicy must authorize that user
// and action. The committed original command, positive registration binding and
// immutable input provenance must all match; neutral acknowledgements, missing,
// pending, aborted, retired and foreign origins cannot disclose input.
//
// The native owner must first authenticate the signed original registration
// proof, then authenticate this ciphertext and its complete binding, reconstruct
// the original email intent and authorize it with the email policy. This read
// grants neither mailbox ownership, current identity/session authority nor
// permission to consume. Confirmation must recheck current state and atomically
// mutate identity and consume the proof through the sole Coordinator transaction.
// No original cookie, live pre-auth flow or regenerated credential is required.
//
// Returned bytes are caller-owned sensitive custody: clear them after use and
// never log/serialize them. No transaction, callback under locks, preparation,
// generation, takeover, mutation or goroutine is created. The pool is borrowed;
// immutable configuration permits concurrent calls. MaximumDuration and earlier
// deadlines bound all reads and policy work. Failure returns zero custody and
// typed redacted errors. Existing original-actor recovery APIs are unchanged.
func (c *Coordinator) QueryRegistrationPreparation(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, feature FeatureRegistration, owner RequestKeyPreparationContributor) (binding RequestKeyPreparationBinding, wire []byte, err error) {
	if ctx == nil || c == nil || c.pool == nil || c.pool.Raw() == nil || c.commandRead == nil || c.requestKeys == nil || !validRequestKeyConfig(*c.requestKeys) || c.queryPolicy == nil || !validCommandQueryPolicy(*c.queryPolicy) || c.maximumDuration <= 0 || c.maximumDuration > time.Minute || !passwordRegistrationOperation(feature.Operation) || feature.Operation.SubjectRequirement != identity.FeatureSubjectAnonymousFlow || q.OperationID != "identity.email.verification-confirm" || q.AnonymousFlowID != "" || q.RecordID != "" || q.LinkMode != 0 || !queryScopeText(string(q.UserID)) {
		return binding, nil, invalidPreparation()
	}
	scope := RequestKeyScope{TenantID: q.TenantID, ActorID: q.ActorID, ActorKind: q.ActorKind, Method: "POST", RouteID: feature.Operation.OperationID}
	if _, e := identity.ParseCommandID(string(q.CommandID)); e != nil || !validRequestKeyScope(scope) || c.validateRequestPreparation(scope, feature, owner) != nil {
		return binding, nil, invalidPreparation()
	}
	ctx, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
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
			binding, wire = RequestKeyPreparationBinding{}, nil
		}
	}()
	if ctx.Err() != nil {
		return binding, nil, readFailure(ctx, ctx.Err())
	}
	allowed, policyErr := c.authorizeCommandQuery(ctx, q, caller)
	observed, observeErr := c.commandRead(ctx, q.CommandID)
	id, _ := base64.RawURLEncoding.DecodeString(string(q.CommandID))
	var registered bool
	registrationErr := c.pool.Raw().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.registration_bindings WHERE tenant_id=$1 AND purpose='identity.password.signup' AND command_id=$2 AND user_id=$3)`, string(q.TenantID), id, string(q.UserID)).Scan(&registered)
	if ctx.Err() != nil {
		return binding, nil, readFailure(ctx, ctx.Err())
	}
	if policyErr != nil || !allowed {
		if policyErr != nil {
			return binding, nil, identity.UnavailableError{}
		}
		return binding, nil, identity.ForbiddenError{}
	}
	if observeErr != nil {
		return binding, nil, readFailure(ctx, observeErr)
	}
	if registrationErr != nil {
		return binding, nil, identity.UnavailableError{}
	}
	b, operation, decodeErr := decodeObservedScope(observed.scope)
	if decodeErr != nil || operation == nil || *operation != feature.Operation || b.CommandID != q.CommandID || b.TenantID != q.TenantID || b.UserID != "" || b.AnonymousFlowID == "" || !registered {
		return binding, nil, identity.ForbiddenError{}
	}
	original := identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}
	receipt, receiptErr := commandReceipt(original, observed, nil)
	if receiptErr != nil || receipt.Outcome != identity.CommitOutcomeCommitted {
		if receiptErr != nil {
			return binding, nil, receiptErr
		}
		return binding, nil, identity.ForbiddenError{}
	}
	return c.readRequestPreparation(ctx, original, feature, observed, false)
}
