package passwordpostgres

import (
	"context"
	"encoding/base64"

	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/phone"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RecoverVerification authenticates committed original sending custody, actual
// source-session possession/current synchronizer and current query permission.
// It observes/reconciles only the exact original OTP attempt through the existing
// journal. It compares no code, creates no attempt, charges no counter, emits no
// projection/session and never infers success from today's verified number.
func (s *PhoneVerificationService) RecoverVerification(ctx context.Context, r phone.VerificationRecoveryRequest) (out phone.VerificationResult, err error) {
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
	var result phone.VerificationResultSpec
	entered := false
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
			if entered {
				result.Outcome = identity.CommitOutcomeUnknown
			}
		}
		if result.Binding.CommandID != "" {
			mapped, e := phone.NewVerificationResult(result)
			if e != nil {
				err = identity.UnavailableError{}
			} else {
				out = mapped
			}
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	original, err := request.Recovery.Bindings()
	if err != nil {
		return out, err
	}
	source, confirmation, err := state.restorePhoneSource(ctx, request.TenantID, request.UserID, request.Caller, request.Flow, original.SendCommandID, request.CSRFToken)
	if err != nil {
		return out, err
	}
	before, err := state.currentPhoneSource(ctx, request.Caller, source, false)
	if err != nil {
		return out, err
	}
	p := &phoneConfirmationPhase{service: state, source: source, confirmation: confirmation, csrf: request.CSRFToken}
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
	op := phoneVerificationOperation()
	b.OperationID, b.SchemaID, b.SchemaVersion = op.OperationID, op.SchemaID, op.SchemaVersion
	b.CommandID = original.Attempt.CommandID
	b.CorrelationID = string(b.CommandID)
	q := phoneRecoveryQuery(b)
	caller := state.phoneQueryCaller(request.Caller, q, true)
	entered = true
	receipt, queryErr := p.coordinator.RecoverOTPFeatureCommand(ctx, q, plan, caller)
	if receipt.Validate() != nil || receipt.Feature == nil || receipt.Feature.Operation != op || receipt.Binding.CommandID != b.CommandID || receipt.Binding.TenantID != request.TenantID || receipt.Binding.UserID != request.UserID || receipt.Binding.RecordID != b.RecordID {
		return out, identity.UnavailableError{}
	}
	after, err := state.currentPhoneSource(ctx, request.Caller, source, false)
	if err != nil {
		return out, err
	}
	if after != before {
		return out, identity.ForbiddenError{}
	}
	// Historical metadata is disclosure too. Keep the public result empty until
	// both current-policy observations agree; a late denial must not leak the
	// receipt merely because the original journal query already returned it.
	result = phone.VerificationResultSpec{Binding: receipt.Binding, Outcome: receipt.Outcome, RetryAfter: receipt.RetryAfter, Recovery: request.Recovery, Replayed: true}
	if queryErr != nil && receipt.Outcome != identity.CommitOutcomeNotCommitted {
		return out, queryErr
	}
	return out, nil
}
