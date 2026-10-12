package risk

import "time"

// PrepareMFACompletion selects the anonymous original-continuation counter
// projection only for identity.mfa.totp-verify or identity.mfa.recovery-use. The native MFA owner must
// authenticate subject.User and capabilityID against the original signed child
// and frozen MFA completion plan; scalar construction is not authority. Only
// User and trusted Network may be populated. No session identity is fabricated.
//
// Preserve canonical CredentialMutation phase, limits, window, threshold and
// failure policy. Replace only the session dimension with the original child
// capability dimension, retaining tenant and subject protection across children.
// Ordinary session-based enrollment/step-up and registration verification remain
// disjoint. Native risk charging must share the attempted command transaction,
// including denied factor attempts. Preparation is pure and never charges,
// consumes, authorizes, samples a clock or renews the supplied primary time.
func (p CommandCounterPolicy) PrepareMFACompletion(scope Context, subject Subject, capabilityID string, primaryTime time.Time) (CounterCommand, error) {
	if !mfaCompletionCounterAction(scope.Operation) {
		return CounterCommand{}, ErrInvalidCounterCommand
	}
	return p.prepareCapabilityCounter(scope, subject, capabilityID, primaryTime, scope.Operation)
}

// ValidateMFACompletion compares exact original tenant/action/attempt/user/
// network/child and this policy's retained-key custody at exclusive original
// evidence expiry. It does not authenticate the child or grant allowance.
// Changed, expired, foreign and other-profile commands fail closed; no evidence
// freshness is reset. Concurrent immutable calls are safe and retain no inputs.
func (p CommandCounterPolicy) ValidateMFACompletion(command CounterCommand, scope Context, subject Subject, capabilityID string, primaryTime time.Time) error {
	if !mfaCompletionCounterAction(scope.Operation) {
		return ErrInvalidCounterCommand
	}
	return p.validateCapabilityCounter(command, scope, subject, capabilityID, primaryTime, scope.Operation)
}

func mfaCompletionCounterAction(action Action) bool {
	return action == "identity.mfa.totp-verify" || action == "identity.mfa.recovery-use"
}
