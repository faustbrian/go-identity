package postgres

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"math"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// ExecutePreparedAPIKeyVerification submits a closed native verification
// preparation through the existing coordinator and returns the original claim
// fingerprint actually matched under its reservation lock. A retained older
// key may win even after a prospective absence observation used a newer key.
// The returned nonzero commitment must accompany original outcome recovery,
// including failed acknowledgement; it is not proof of commit or authority.
// Zero means no matching claim was established. No second journal, credential
// comparison or freshness source is introduced. Other feature profiles use
// ExecutePreparedFeature and cannot request this output.
// Original must bind the declared KeyVersion in its uint64 field
// apikey.verify.key-version so a later invocation cannot substitute that fence.
func (c *Coordinator) ExecutePreparedAPIKeyVerification(ctx context.Context, original identity.Command, declaration CommandPlan) (result identity.CommandResult, fingerprint [32]byte, err error) {
	spec, ok := original.Feature()
	if !ok || !validAPIKeyVerificationPlan(spec.Binding, declaration) || !apiKeyVerificationDeclarationMatches(original, declaration) || c == nil || c.admissionPolicy == nil || c.queryPolicy == nil {
		return result, fingerprint, invalidPlan()
	}
	result, err = c.executePreparedFeatureCaptured(ctx, nil, original, declaration, &fingerprint)
	return result, fingerprint, err
}

func apiKeyVerificationDeclarationMatches(command identity.Command, plan CommandPlan) bool {
	spec, ok := command.Feature()
	if !ok || plan.APIKeyVerification == nil {
		return false
	}
	for _, field := range spec.Fields {
		if field.Name == "apikey.verify.key-version" {
			return field.Value.Kind == identity.FeatureUint64 && field.Value.Uint64 == plan.APIKeyVerification.KeyVersion
		}
	}
	return false
}

// ObserveAPIKeyVerificationCommand binds a trusted native verifier's complete
// original command to the sole coordinator claim. Authorized primary absence
// returns the prospective current-key fingerprint and Absent; existing history
// returns its exact retained-key fingerprint only after full intent comparison.
// Absence is neither reservation nor proof of rollback. Current AdmissionPolicy
// and the registered APIKeyVerificationContributor are mandatory. The read is
// bounded, uncached and effect-free; no participant, transaction or credential
// comparison is invoked. Generic metadata APIs still hide fingerprints.
//
// Native code must preserve the actual commitment returned by
// ExecutePreparedAPIKeyVerification, not this prospective value, on ambiguous
// submission. Returned history never
// authenticates a credential or refreshes original validity. Concurrent calls
// share only immutable configuration; the caller retains pool ownership.
func (c *Coordinator) ObserveAPIKeyVerificationCommand(ctx context.Context, command identity.Command, caller authorization.DecisionContext) (CommandAdmission, [32]byte, error) {
	zero := func(err error) (CommandAdmission, [32]byte, error) { return CommandAdmission{}, [32]byte{}, err }
	if ctx == nil || c == nil || c.registry == nil || c.commandRead == nil || c.admissionPolicy == nil || c.maximumDuration <= 0 || c.maximumDuration > time.Minute {
		return zero(coordinatorError())
	}
	spec, ok := command.Feature()
	if !ok || spec.Operation != apiKeyVerificationOperation(spec.Binding.UserID == "") || spec.Binding.ValidateFor(spec.Operation) != nil {
		return zero(invalidPlan())
	}
	b := spec.Binding
	if b.UserID != "" && b.ActorKind != authorization.SubjectAPIKey || b.UserID == "" && (b.ActorKind != authorization.SubjectServiceAccount || b.AnonymousFlowID != string(b.CommandID)) {
		return zero(invalidPlan())
	}
	entry, err := c.registry.selectFeatureOperation(FeatureRegistration{Contributor: apiKeyVerificationDescriptor(), Operation: spec.Operation})
	if err != nil {
		return zero(invalidPlan())
	}
	if _, ok := entry.contributor.(APIKeyVerificationContributor); !ok {
		return zero(invalidPlan())
	}
	claim, err := prepareClaim(command, c.keys.retained[c.keys.current])
	if err != nil || !validClaim(claim, c.keys) {
		return zero(invalidPlan())
	}
	q := creationRecoveryQuery(spec.Binding)
	q.AnonymousFlowID = spec.Binding.AnonymousFlowID
	ctx, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	allowed, policyErr := authorizeCommandObservation(ctx, q, caller, c.admissionPolicy, true)
	observed, readErr := c.commandRead(ctx, q.CommandID)
	if ctx.Err() != nil || readErr != nil && !errors.Is(readErr, pgx.ErrNoRows) {
		return zero(readFailure(ctx, readErr))
	}
	if policyErr != nil {
		return zero(identity.UnavailableError{})
	}
	if !allowed {
		return zero(identity.ForbiddenError{})
	}
	if errors.Is(readErr, pgx.ErrNoRows) {
		return CommandAdmission{Absent: true}, claimFingerprint(c.keys.retained[c.keys.current], claim.canonical), nil
	}
	receipt, receiptErr := commandReceipt(q, observed, nil)
	if receipt.Outcome == identity.CommitOutcomeInvalid {
		return zero(receiptErr)
	}
	if observed.fingerprintKeyVersion < 1 || observed.fingerprintKeyVersion > math.MaxUint32 {
		return zero(identity.UnavailableError{})
	}
	key, ok := c.keys.retained[uint32(observed.fingerprintKeyVersion)]
	if !ok {
		return zero(identity.UnavailableError{})
	}
	retained, err := prepareClaim(command, key)
	if err != nil {
		return zero(err)
	}
	fingerprint := claimFingerprint(key, retained.canonical)
	if !bytes.Equal(retained.safeFields, observed.scope) || !hmac.Equal(fingerprint[:], observed.fingerprint) {
		return zero(identity.ConflictError{CommandID: q.CommandID})
	}
	if err := checkAPIKeyVerificationObservation(q, fingerprint)(observed); err != nil {
		return zero(err)
	}
	return CommandAdmission{Record: commandRecord(receipt)}, fingerprint, receiptErr
}

// RecoverAPIKeyVerificationCommand narrows existing feature recovery to the
// exact original API-key attempt and nonzero coordinator fingerprint. Current
// QueryPolicy still authorizes the read. A mismatch fails before taking recovery
// locks or invoking participants; the same check repeats under the journal's
// existing recovery locks. Missing history never proves noncommit. No secret,
// native result or principal is returned, and no credential comparison, new
// command, alternate journal or freshness renewal occurs. Earlier deadlines win.
func (c *Coordinator) RecoverAPIKeyVerificationCommand(ctx context.Context, q identity.RecoveryQuery, fingerprint [32]byte, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if ctx == nil || c == nil || c.maximumDuration <= 0 || c.maximumDuration > time.Minute || q.OperationID != "identity.apikey.verify" || fingerprint == ([32]byte{}) {
		return identity.CommandResult{}, invalidPlan()
	}
	ctx, stop := context.WithTimeout(ctx, c.maximumDuration)
	defer stop()
	check := checkAPIKeyVerificationObservation(q, fingerprint)
	preparedOnly := false
	result, err := c.queryCommandReceiptChecked(ctx, q, caller, func(observed commandObservation) error {
		if err := check(observed); err != nil {
			return err
		}
		binding, operation, scopeErr := commandObservationScope(q, observed, nil)
		preparedOnly = scopeErr == nil && pendingAPIKeyPreparation(binding, operation, observed)
		return nil
	})
	if err == nil && preparedOnly && result.Outcome == identity.CommitOutcomeInProgress {
		// An unattached native preparation has no frozen final participants.
		// Preserve uncertainty, even after lease expiry; absent output cannot
		// prove noncommit or authorize another generation/comparison.
		return result, nil
	}
	return c.reconcileFeatureReceipt(ctx, q, result, err, check)
}

func pendingAPIKeyPreparation(binding identity.CommandBinding, operation *identity.FeatureOperation, observed commandObservation) bool {
	return operation != nil && *operation == apiKeyVerificationOperation(binding.UserID == "") && binding.ValidateFor(*operation) == nil && observed.plan == nil && observed.state != nil && *observed.state == "pending" && observed.preparationProfile != nil && (*observed.preparationProfile == 1 || *observed.preparationProfile == 2) && len(observed.fingerprint) == 32 && observed.resultVersion == nil && observed.class == nil && observed.result == nil
}

func checkAPIKeyVerificationObservation(q identity.RecoveryQuery, fingerprint [32]byte) func(commandObservation) error {
	return func(observed commandObservation) error {
		if !hmac.Equal(fingerprint[:], observed.fingerprint) {
			return identity.ConflictError{CommandID: q.CommandID}
		}
		b, op, err := commandObservationScope(q, observed, nil)
		if err != nil || op == nil || *op != apiKeyVerificationOperation(b.UserID == "") {
			return identity.ForbiddenError{}
		}
		if pendingAPIKeyPreparation(b, op, observed) {
			return nil
		}
		plan, _, err := observedCommandPlan(b, op, observed)
		if err != nil || !validAPIKeyVerificationPlan(b, plan) {
			return identity.UnavailableError{}
		}
		return nil
	}
}
