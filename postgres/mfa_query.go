package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"time"

	authorization "github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// QueryMFATOTPCommand compares original opaque TOTP input against retained
// command history under its original fingerprint key. It requires current
// query authorization but no live factor or mutable continuation projection:
// a counted denial must remain retryable after its budget version advances.
// The original frozen native completion plan is validated, never replaced.
//
// The boolean reports authorized presence, including conflicting input. Only
// authorized absence returns false with nil error. Retired or unavailable
// evidence fails closed. Receipts are historical metadata, not permission to
// authenticate or reveal a session. No participant, code comparison, generation,
// reservation, consumption, mutation or recovery is invoked by this read.
func (c *Coordinator) QueryMFATOTPCommand(ctx context.Context, command identity.Command, caller authorization.DecisionContext) (identity.CommandResult, bool, error) {
	return c.queryMFACommand(ctx, command, caller, "identity.mfa.totp-verify")
}

// QueryMFARecoveryCommand observes authorized original recovery-code history
// using its retained fingerprint key and frozen plan, without comparing against
// stored codes or charging an attempt. Matching denied retries remain observable
// after continuation changes; changed code/browser conflicts. Retired, missing
// or corrupt evidence fails closed. Presence includes conflicting input; only
// authorized absence returns false with no error. A receipt grants no factor
// authority, session delivery or permission to repeat uncertain consumption.
func (c *Coordinator) QueryMFARecoveryCommand(ctx context.Context, command identity.Command, caller authorization.DecisionContext) (identity.CommandResult, bool, error) {
	return c.queryMFACommand(ctx, command, caller, "identity.mfa.recovery-use")
}

// QueryMFAOTPCommand observes the original opaque OTP/browser submission under
// its retained fingerprint key and current query authorization. Terminal denial
// or success is historical: it requires no live continuation, factor, OTP
// comparison or renewed allowance. Changed input conflicts, corrupt or retired
// custody denies, and only authorized absence returns false without an error.
// The returned receipt cannot disclose a session or authorize another attempt.
func (c *Coordinator) QueryMFAOTPCommand(ctx context.Context, command identity.Command, caller authorization.DecisionContext) (identity.CommandResult, bool, error) {
	return c.queryMFACommand(ctx, command, caller, "identity.mfa.otp-verify")
}

func (c *Coordinator) queryMFACommand(ctx context.Context, command identity.Command, caller authorization.DecisionContext, operation string) (identity.CommandResult, bool, error) {
	return c.withMFACommandObservation(ctx, command, caller, operation, func(_ context.Context, spec identity.FeatureCommandSpec, _ [32]byte, observed commandObservation) (identity.CommandResult, error) {
		query := creationRecoveryQuery(spec.Binding)
		query.AnonymousFlowID = spec.Binding.AnonymousFlowID
		// An acknowledged OTP preparation may precede final-plan attachment.
		// Original fingerprint/scope still permit only a pending receipt, never
		// inference of rollback, new entropy or a completed authentication.
		if operation == "identity.mfa.otp-verify" && observed.plan == nil && observed.declaration == nil && observed.state != nil && *observed.state == "pending" && observed.resultVersion == nil && observed.class == nil && observed.result == nil {
			if observed.until == nil || !postgresExactTime(*observed.until) || !postgresExactTime(observed.now) {
				return identity.CommandResult{}, identity.UnavailableError{}
			}
			retry := observed.until.Sub(observed.now)
			if retry < time.Microsecond {
				retry = time.Microsecond
			} else if retry > time.Minute {
				retry = time.Minute
			}
			return featureOutcome(spec.Binding, &spec.Operation, identity.CommitOutcomeInProgress, retry), nil
		}
		plan, _, err := observedCommandPlan(spec.Binding, &spec.Operation, observed)
		if err != nil || !validMFACompletionPlan(spec.Binding, plan) || plan.Feature.Operation != spec.Operation {
			return identity.CommandResult{}, identity.UnavailableError{}
		}
		return commandReceipt(query, observed, nil)
	})
}

func (c *Coordinator) withMFACommandObservation(ctx context.Context, command identity.Command, caller authorization.DecisionContext, operation string, visit func(context.Context, identity.FeatureCommandSpec, [32]byte, commandObservation) (identity.CommandResult, error)) (identity.CommandResult, bool, error) {
	if ctx == nil || c == nil || c.commandRead == nil || c.queryPolicy == nil || c.admissionPolicy == nil || c.maximumDuration <= 0 {
		return identity.CommandResult{}, false, coordinatorError()
	}
	spec, ok := command.Feature()
	var opaque bool
	switch operation {
	case "identity.mfa.totp-verify", "identity.mfa.otp-verify":
		_, opaque = command.OneTimeCode()
	case "identity.mfa.recovery-use":
		_, opaque = command.RecoveryCode()
	}
	if !ok || !opaque || spec.Operation.OperationID != operation || !mfaCompletionOperation(spec.Operation) {
		return identity.CommandResult{}, false, invalidPlan()
	}
	if _, err := prepareClaim(command, c.keys.retained[c.keys.current]); err != nil {
		return identity.CommandResult{}, false, err
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	if bounded.Err() != nil {
		return identity.CommandResult{}, false, readFailure(bounded, bounded.Err())
	}
	query := creationRecoveryQuery(spec.Binding)
	query.AnonymousFlowID = spec.Binding.AnonymousFlowID
	allowed, policyErr := c.authorizeCommandQuery(bounded, query, caller)
	admitted, admissionErr := authorizeCommandObservation(bounded, query, caller, c.admissionPolicy, true)
	observed, readErr := c.commandRead(bounded, spec.Binding.CommandID)
	if bounded.Err() != nil {
		return identity.CommandResult{}, false, readFailure(bounded, bounded.Err())
	}
	if policyErr != nil || admissionErr != nil {
		return identity.CommandResult{}, false, identity.UnavailableError{}
	}
	if !allowed || !admitted {
		return identity.CommandResult{}, false, identity.ForbiddenError{}
	}
	if errors.Is(readErr, pgx.ErrNoRows) {
		return identity.CommandResult{}, false, nil
	}
	if _, _, err := commandObservationScope(query, observed, readErr); err != nil {
		return identity.CommandResult{}, false, err
	}
	if observed.fingerprintKeyVersion < 1 || observed.fingerprintKeyVersion > 4294967295 {
		return identity.CommandResult{}, true, identity.UnavailableError{}
	}
	key, retained := c.keys.retained[uint32(observed.fingerprintKeyVersion)]
	if !retained {
		return identity.CommandResult{}, true, identity.UnavailableError{}
	}
	claim, err := prepareClaim(command, key)
	if err != nil {
		return identity.CommandResult{}, true, err
	}
	fp := claimFingerprint(key, claim.canonical)
	if !bytes.Equal(claim.safeFields, observed.scope) || !hmac.Equal(fp[:], observed.fingerprint) {
		return featureOutcome(spec.Binding, &spec.Operation, identity.CommitOutcomeConflict, 0), true, identity.ConflictError{CommandID: spec.Binding.CommandID}
	}
	result, err := visit(bounded, spec, fp, observed)
	return result, true, err
}
