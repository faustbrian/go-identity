package delivery

import "time"

// ReceiptSnapshot is the owned adapter's locked observation of one effect.
// Generation is positive and State is a durable state. ObservedAt is the last
// applied provider observation, or zero before any provider evidence. These
// fields convey no authentication, tenant authority, lease or CAS proof.
type ReceiptSnapshot struct {
	State      DeliveryState
	Generation uint32
	ObservedAt time.Time
}

// ReceiptDecision proposes a monotonic provider-evidence transition. The adapter
// must authenticate evidence and bind its tenant/provider/effect before deciding,
// then atomically persist the result, event dedupe, observation and required
// ciphertext erasure under generation CAS. Advanced denotes a state change, not
// a new event or observation time. No decision admits a retry or provider call.
type ReceiptDecision struct {
	State        DeliveryState
	ObservedAt   time.Time
	Advanced     bool
	ErasePayload bool
}

// Validate checks bounded normalized receipt shape only. Provider names and
// event IDs are not authentication; verification belongs to the owned adapter.
// Only accepted/delivered/rejected/bounced/cancelled/unknown provider statuses
// are allowed. Retry admission is deliberately not a receipt classification.
func (r ReceiptRecordRequest) Validate() error {
	if !validTarget(r.TenantID, r.IntentID) || !purposeName(r.Provider) || !printableASCII(r.ProviderEventID, 1, 256) || r.Generation == 0 || !validUTCTime(r.ObservedAt) || !printableASCII(r.IdempotencyKey, 16, 128) {
		return ErrInvalidInput
	}
	switch r.Status {
	case StateAccepted, StateDelivered, StateRejected, StateBounced, StateCancelled, StateOutcomeUnknown:
		return nil
	default:
		return ErrInvalidInput
	}
}

// DecideReceipt applies the shared callback/reconciliation ordering policy with
// constant bounded work and no I/O, clock, store or retained mutable state.
// Earlier observations are no-ops; conflicting observations at the same instant
// or conflicting newer terminal outcomes require explicit operator resolution.
// Later accepted/unknown evidence cannot downgrade acceptance or a terminal
// outcome. Cancellation can be confirmed only from OutcomeUnknown; local
// cancellation must first fence submissions and record that uncertainty.
// Terminal no-ops still demand ciphertext erasure to repair legacy rows.
// Invalid shapes return ErrInvalidInput, fences/transitions ErrConflict; errors
// return a zero decision. Caller-owned input must not mutate during the call.
func DecideReceipt(current ReceiptSnapshot, evidence ReceiptRecordRequest) (ReceiptDecision, error) {
	if !durableState(current.State) || current.Generation == 0 || !current.ObservedAt.IsZero() && !validUTCTime(current.ObservedAt) || evidence.Validate() != nil {
		return ReceiptDecision{}, ErrInvalidInput
	}
	if current.Generation != evidence.Generation || current.State == StateQueued {
		return ReceiptDecision{}, ErrConflict
	}
	decision := ReceiptDecision{State: current.State, ObservedAt: current.ObservedAt, ErasePayload: terminalState(current.State)}
	if !current.ObservedAt.IsZero() {
		if evidence.ObservedAt.Before(current.ObservedAt) {
			return decision, nil
		}
		if evidence.ObservedAt.Equal(current.ObservedAt) && evidence.Status != current.State {
			return ReceiptDecision{}, ErrConflict
		}
	}
	if evidence.Status == current.State {
		decision.ObservedAt = evidence.ObservedAt
		return decision, nil
	}
	if evidence.Status == StateOutcomeUnknown && current.State != StateAttempting && current.State != StateRetryWait || evidence.Status == StateAccepted && terminalState(current.State) {
		return decision, nil
	}
	if terminalState(current.State) || evidence.Status == StateCancelled && current.State != StateOutcomeUnknown {
		return ReceiptDecision{}, ErrConflict
	}
	decision.State = evidence.Status
	decision.ObservedAt = evidence.ObservedAt
	decision.Advanced = true
	decision.ErasePayload = terminalState(evidence.Status)
	return decision, nil
}
