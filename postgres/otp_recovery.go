package postgres

import (
	"context"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// RecoverOTPAttemptDenial observes the original command AND server-issued
// attempt without submitted code, comparison, charge, mutation or takeover.
// Caller must supply the original complete private attempt projection; neither
// command nor attempt possession authorizes disclosure. The existing current
// QueryPolicy and bounded primary read apply, including constant decision/read
// shape for valid denied requests. A changed attempt returns zero and Forbidden.
// Pending history remains InProgress, never proof of rollback or permission to
// replace the attempt. NotCommitted plus Forbidden is the historical denied
// result; committed/other terminal classes are not this narrow denial protocol.
// This does not recover or release a consuming reservation. Earlier deadlines
// win; no code or contributor callbacks are required or invoked.
func (c *Coordinator) RecoverOTPAttemptDenial(ctx context.Context, q identity.RecoveryQuery, expected OTPAttemptPlan, caller authorization.DecisionContext) (identity.CommandResult, error) {
	if validateOTPPlan(CommandPlan{OTP: &expected, Feature: &FeatureRegistration{}, SubjectType: "attempt"}) != nil {
		return identity.CommandResult{}, invalidPlan()
	}
	return c.queryCommandReceiptChecked(ctx, q, caller, func(o commandObservation) error {
		b, feature, err := decodeObservedScope(o.scope)
		if err != nil || feature == nil || len(o.fingerprint) != 32 {
			return identity.UnavailableError{}
		}
		p, err := decodeFeaturePlan(b, [32]byte(o.fingerprint), o.plan)
		if err != nil {
			return identity.UnavailableError{}
		}
		if p.OTP == nil || *p.OTP != expected {
			return identity.ForbiddenError{}
		}
		if o.state == nil || *o.state != "pending" && (*o.state != "aborted" || o.class == nil || *o.class != "denied") {
			return identity.UnavailableError{}
		}
		return nil
	})
}
