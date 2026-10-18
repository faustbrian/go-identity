package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// QueryPasswordMFAChallenge returns authorized original password-signin history
// and its closed MFA profile discriminator. Challenge scope is disclosed only
// for committed history; pending/aborted observations contain zero scope. False
// identifies an ordinary password-signin profile, not absence or rollback.
// This uses the existing query policy, journal and canonical frozen-plan decoder.
// It performs no reconciliation, signing, callback under locks or lease renewal.
// Returned metadata is historical correlation, never primary/factor authority.
// Earlier deadlines win and all operational errors remain redacted.
func (c *Coordinator) QueryPasswordMFAChallenge(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (MFAContinuationPlan, CommandRecord, bool, error) {
	if q.OperationID != "identity.password.signin" || q.UserID != "" || q.AnonymousFlowID == "" || q.RecordID != "" {
		return MFAContinuationPlan{}, CommandRecord{}, false, identity.InvalidInputError{Field: "password_mfa_query"}
	}
	return c.queryPrimaryMFAChallenge(ctx, q, caller, false)
}

func (c *Coordinator) queryPrimaryMFAChallenge(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext, verification bool) (MFAContinuationPlan, CommandRecord, bool, error) {
	var original MFAContinuationPlan
	var present bool
	receipt, err := c.queryCommandReceiptChecked(ctx, q, caller, func(observed commandObservation) error {
		binding, feature, e := commandObservationScope(q, observed, nil)
		if e != nil || feature == nil || len(observed.fingerprint) != 32 {
			return identity.UnavailableError{}
		}
		plan, e := decodeFeaturePlan(binding, [32]byte(observed.fingerprint), observed.plan)
		if e != nil {
			return e
		}
		if plan.MFAContinuation == nil {
			return nil
		}
		matched := passwordMFAOperation(plan)
		if verification {
			matched = emailVerificationMFAOperation(plan)
		}
		if !matched || plan.CapabilityIssuance == nil {
			return identity.UnavailableError{}
		}
		present = true
		original = *plan.MFAContinuation
		return nil
	})
	if receipt.Outcome != identity.CommitOutcomeCommitted {
		original = MFAContinuationPlan{}
	}
	return original, commandRecord(receipt), present, err
}
