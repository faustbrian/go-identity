package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"

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
	if ctx == nil || c == nil || c.commandRead == nil || c.queryPolicy == nil || c.admissionPolicy == nil || c.maximumDuration <= 0 {
		return identity.CommandResult{}, false, coordinatorError()
	}
	spec, ok := command.Feature()
	_, opaque := command.OneTimeCode()
	if !ok || !opaque || spec.Operation.OperationID != "identity.mfa.totp-verify" || !mfaCompletionOperation(spec.Operation) {
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
	plan, err := decodeFeaturePlan(spec.Binding, fp, observed.plan)
	if err != nil || !validMFACompletionPlan(spec.Binding, plan) || plan.OTP != nil || plan.Feature.Operation != spec.Operation {
		return identity.CommandResult{}, true, identity.UnavailableError{}
	}
	result, err := commandReceipt(query, observed, nil)
	return result, true, err
}
