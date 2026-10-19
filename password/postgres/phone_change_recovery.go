package passwordpostgres

import (
	"context"
	"encoding/base64"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
)

var _ phone.ChangeService = (*PhoneChangeService)(nil)

// Every keyed history path uses the same original-custody, current-authority
// and before/after query fences as explicit recovery. A failed fence returns no
// receipt; a remembered request key is correlation, never disclosure authority.
func (s *PhoneChangeService) recoverSubmittedUpdate(ctx context.Context, r phone.UpdateRequestSpec, recovery phone.VerificationRecovery) (phone.UpdateResult, error) {
	caller := r.Caller.Clone()
	caller.Request.Action = "identity.phone.update.recover"
	history, err := phone.NewUpdateRecoveryRequest(phone.UpdateRecoveryRequestSpec{TenantID: r.TenantID, UserID: r.UserID, Caller: caller, Flow: r.Flow, Recovery: recovery, CSRFToken: r.CSRFToken})
	if err != nil {
		return phone.UpdateResult{}, err
	}
	return s.RecoverUpdate(ctx, history)
}

// RecoverUpdate authenticates original committed sending custody and session
// possession, then discloses/reconciles only the exact original code-free OTP
// attempt under current account/credential/query authority. Identifier changes
// do not renew the old session or confer new authentication. This operation
// compares no code, consumes no proof and emits no new notice or cascade.
func (s *PhoneChangeService) RecoverUpdate(ctx context.Context, r phone.UpdateRecoveryRequest) (out phone.UpdateResult, err error) {
	state := s.state()
	if ctx == nil || state == nil {
		return out, password.ErrPasswordWork
	}
	request, err := r.Bindings()
	if err != nil {
		return out, err
	}
	ctx, stop := context.WithTimeout(ctx, state.config().MaximumDuration)
	defer stop()
	defer func() {
		if recover() != nil {
			out, err = phone.UpdateResult{}, identity.UnavailableError{}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	original, err := request.Recovery.Bindings()
	if err != nil {
		return out, err
	}
	source, confirmation, err := state.restoreChangeSource(ctx, request.TenantID, request.UserID, request.Caller, request.Flow, original.SendCommandID, request.CSRFToken)
	if err != nil {
		return out, err
	}
	// This adapter uses only the common current-history fence, never enrollment
	// admission, target derivation or issuer. Both workflows conserve the same
	// actual account/password/session/query owners while permitting old epochs.
	historySource := &phoneEnrollmentPhase{primary: source.primary, command: source.command}
	before, err := state.common.currentPhoneSourceForAction(ctx, request.Caller, historySource, false, "identity.phone.update.recover")
	if err != nil {
		return out, err
	}
	p := &phoneChangeUpdatePhase{service: state, source: source, confirmation: confirmation}
	p.intent, err = confirmation.Intent()
	if err != nil {
		return out, err
	}
	p.coordinator, p.registry, err = state.coordinator(p, confirmation.Contributor())
	if err != nil {
		return out, err
	}
	fingerprint, err := base64.RawURLEncoding.Strict().DecodeString(string(original.Attempt.Fingerprint))
	if err != nil || len(fingerprint) != 32 {
		clear(fingerprint)
		return out, password.ErrPasswordWork
	}
	defer clear(fingerprint)
	plan := kernel.OTPAttemptPlan{AttemptID: string(original.Attempt.AttemptID), AttemptFingerprint: [32]byte(fingerprint), FingerprintKeyVersion: original.Attempt.FingerprintKeyVersion, ChallengeID: string(original.SendCommandID), ScopeDigest: original.ScopeDigest, DigestKeyVersion: original.DigestKeyVersion, ExpectedVersion: original.ExpectedVersion, Mode: kernel.OTPConsume}
	b := sourceBinding(source.command)
	op := actionPrimaryOperation("identity.phone.update")
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.CommandID, b.CorrelationID, b.RecordID = original.Attempt.CommandID, string(original.Attempt.CommandID), string(p.intent.Change.ID)
	q := phoneRecoveryQuery(b)
	caller := state.common.phoneQueryCaller(request.Caller, q, true)
	receipt, queryErr := p.coordinator.RecoverOTPFeatureCommand(ctx, q, plan, caller)
	if receipt.Validate() != nil || receipt.Feature == nil || receipt.Feature.Operation != op || receipt.Binding != b {
		return out, identity.UnavailableError{}
	}
	after, err := state.common.currentPhoneSourceForAction(ctx, request.Caller, historySource, false, "identity.phone.update.recover")
	if err != nil {
		return out, err
	}
	if before != after {
		return out, identity.ForbiddenError{}
	}
	out = phone.UpdateResult{Result: receipt, Recovery: request.Recovery, Replayed: true}
	if queryErr != nil && receipt.Outcome != identity.CommitOutcomeNotCommitted {
		return out, queryErr
	}
	return out, nil
}
