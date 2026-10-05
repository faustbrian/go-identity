package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"

	authentication "github.com/faustbrian/go-authentication"
	authorization "github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// QueryAuthenticatedCommand is the owned final-authentication adapter's bounded
// primary receipt lookup, not a public login route. It requires the original
// native command, opaque proof and prepared plan plus current QueryPolicy
// authorization. It compares the complete intent under the claim's exact
// retained key version and the original frozen plan before returning only the
// supported final-authentication feature receipt. No user/profile payload or
// credential is returned. Generic QueryCommand remains metadata-only.
//
// Original proof expiry is historical on this path: provenance is checked at
// its original issuance instant, never renewed. The receipt grants no current
// session authority or bearer delivery. Missing or retired claims deny without
// disclosing absence; incomplete evidence or missing retained keys fail closed.
// Exact changed input is Conflict. No reservation, lease, proof consumption,
// reconciliation, mutation, transaction or callback under a lock occurs.
func (c *Coordinator) QueryAuthenticatedCommand(ctx context.Context, b identity.CommandBinding, command identity.Command, proof authentication.AuthenticatedProof, plan CommandPlan, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || c == nil || c.commandRead == nil || c.queryPolicy == nil || c.maximumDuration <= 0 {
		return identity.CommandResult{}, coordinatorError()
	}
	claim, snapshot, _, original, err := c.prepareAuthenticated(b, command, proof, plan)
	if err != nil {
		return identity.CommandResult{}, err
	}
	if snapshot.Digest != plan.Digest {
		return identity.CommandResult{}, invalidPlan()
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	if err := bounded.Err(); err != nil {
		return identity.CommandResult{}, readFailure(bounded, err)
	}
	query := creationRecoveryQuery(b)
	allowed, policyErr := c.authorizeCommandQuery(bounded, query, caller)
	observed, readErr := c.commandRead(bounded, b.CommandID)
	if bounded.Err() != nil {
		return identity.CommandResult{}, readFailure(bounded, bounded.Err())
	}
	if policyErr != nil {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	if !allowed {
		return identity.CommandResult{}, identity.ForbiddenError{}
	}
	result, outcomeErr := commandReceipt(query, observed, readErr)
	if result.Outcome == identity.CommitOutcomeInvalid {
		return identity.CommandResult{}, outcomeErr
	}
	if observed.fingerprintKeyVersion < 1 || observed.fingerprintKeyVersion > 4294967295 {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	key, ok := c.keys.retained[uint32(observed.fingerprintKeyVersion)]
	if !ok {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	retained, err := prepareClaim(command, key)
	if err != nil {
		return identity.CommandResult{}, err
	}
	retained, err = bindAuthenticationClaim(retained, original, key)
	if err != nil {
		return identity.CommandResult{}, err
	}
	fingerprint := claimFingerprint(key, retained.canonical)
	if result.Binding != b || !bytes.Equal(claim.safeFields, observed.scope) || !hmac.Equal(observed.fingerprint, fingerprint[:]) {
		return featureOutcome(b, claim.feature, identity.CommitOutcomeConflict, 0), identity.ConflictError{CommandID: b.CommandID}
	}
	expected, err := encodeFeaturePlan(b, fingerprint, snapshot)
	if err != nil {
		return identity.CommandResult{}, invalidPlan()
	}
	if !bytes.Equal(expected, observed.plan) {
		return featureOutcome(b, claim.feature, identity.CommitOutcomeConflict, 0), identity.ConflictError{CommandID: b.CommandID}
	}
	if result.Feature == nil || *claim.feature != result.Feature.Operation {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	return result, outcomeErr
}

// RecoverAuthenticatedCommand reconciles only an already observed exact
// pending command through the existing sole recovery owner, then repeats the
// original-intent receipt lookup. It never reserves or executes a missing
// command, creates a session, replaces a proof or reveals a credential. Live
// leases remain InProgress; ambiguous or incomplete evidence remains unknown.
// Current QueryPolicy and complete original input are required before recovery.
// The original command ID, namespace, policy, plan and retained-key bindings
// cannot change. Returned committed receipts remain historical metadata only.
func (c *Coordinator) RecoverAuthenticatedCommand(ctx context.Context, b identity.CommandBinding, command identity.Command, proof authentication.AuthenticatedProof, plan CommandPlan, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || c == nil || c.maximumDuration <= 0 {
		return identity.CommandResult{}, coordinatorError()
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	result, err := c.QueryAuthenticatedCommand(bounded, b, command, proof, plan, caller)
	if err != nil || result.Outcome != identity.CommitOutcomeInProgress {
		return result, err
	}
	recovered, recoveryErr := c.recoverCommandReceipt(bounded, creationRecoveryQuery(b))
	if recovered.Outcome == identity.CommitOutcomeUnknown || recoveryErr != nil && recovered.Outcome != identity.CommitOutcomeCommitted && recovered.Outcome != identity.CommitOutcomeNotCommitted {
		return featureOutcome(b, &result.Feature.Operation, identity.CommitOutcomeUnknown, 0), identity.UnknownCommitError{CommandID: b.CommandID}
	}
	return c.QueryAuthenticatedCommand(bounded, b, command, proof, plan, caller)
}
