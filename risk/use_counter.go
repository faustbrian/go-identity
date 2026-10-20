package risk

import "time"

// PrepareUseCounters authenticates the original phone evidence and derives its
// existing BeforeCredential counter scope for a native current-state read. The
// original issuance attempt, policy, dimensions and retained key history remain
// unchanged. primaryTime must be coordinator-owned UTC microsecond database time
// within the original exclusive evidence interval. It is not a new evidence
// observation: CheckedAt, issuance/expiry and signed facts are never renewed.
//
// The returned opaque command authenticates the same counter configuration as
// issuance; its projection alone grants no current allowance or Work authority.
// The native counter owner must match the original retained committed attempt,
// then read current windows/rotation history in the same protected transaction.
// This method never charges, dispatches, samples a clock, accesses a provider or
// invokes callbacks. Invalid scope, expiry or zero configuration returns zero
// command and redacted ErrInvalidEvidenceExecution. Concurrent calls are safe.
func (s PhoneEvidenceIssuer) PrepareUseCounters(original PhoneEvidenceRequest, prepared PreparedEvidenceUse, primaryTime time.Time) (CounterCommand, error) {
	if _, err := s.RecheckUse(original, prepared, primaryTime); err != nil {
		return CounterCommand{}, ErrInvalidEvidenceExecution
	}
	binding := original.Recovery.Binding
	scope := Context{Tenant: binding.Tenant, Operation: binding.RecoveryOperation, Attempt: binding.Attempt}
	owner := s.state.evaluation.state.counters
	admission, err := owner.admitScope(scope, BeforeCredential)
	if err != nil {
		return CounterCommand{}, ErrInvalidEvidenceExecution
	}
	command, err := owner.prepareAdmitted(scope, original.Subject, BeforeCredential, admission, primaryTime)
	if err != nil {
		return CounterCommand{}, ErrInvalidEvidenceExecution
	}
	return command, nil
}
