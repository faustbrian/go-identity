package apikey

import (
	"fmt"
	"io"
	"slices"

	identity "github.com/faustbrian/go-identity"
)

// IssuanceOutcome distinguishes authority from response delivery. Status
// recovery can establish commitment but can never establish original delivery
// or reconstruct plaintext. Zero is invalid.
type IssuanceOutcome uint8

const (
	IssuanceUnspecified IssuanceOutcome = iota
	IssuanceCommittedAndRevealed
	IssuanceCommittedDeliveryUnknown
	IssuanceNotCommitted
	IssuanceCommitUnknown
)

// IssuanceResult privately binds a safe committed record and transient
// reveal-once custody. Copies share the same reveal claim. Recovery must pass a
// zero Secret. Formatting and serialization never disclose bearer material.
type IssuanceResult struct{ state *issuanceState }
type issuanceState struct {
	receipt identity.CommandResult
	record  *Record
	secret  Secret
}

// NewIssuanceResult is a trusted adapter projection, not proof of commitment.
// The adapter must obtain outcome from the sole durable coordinator and may
// attach its invocation's fresh secret only for proven committed issuance.
// Noncommitted/unknown observations discard secret custody and forbid records.
func NewIssuanceResult(c Configuration, receipt identity.CommandResult, record *Record, secret Secret) (IssuanceResult, error) {
	if c.Validate() != nil || receipt.Validate() != nil || receipt.Feature == nil || receipt.Feature.Operation.Owner != "identity/apikey" || receipt.Binding.OperationID != "identity.apikey.create" && receipt.Binding.OperationID != "identity.apikey.rotate" {
		return IssuanceResult{}, ErrInvalid
	}
	copyReceipt := receipt
	copyFeature := *receipt.Feature
	copyReceipt.Feature = &copyFeature
	s := &issuanceState{receipt: copyReceipt}
	switch receipt.Outcome {
	case identity.CommitOutcomeCommitted:
		if record == nil || record.Validate(c) != nil || record.ID != KeyID(receipt.Binding.RecordID) || record.Owner.spec.TenantID != receipt.Binding.TenantID || record.Owner.spec.Kind != OwnerUser || record.Owner.spec.UserID != receipt.Binding.UserID {
			return IssuanceResult{}, ErrInvalid
		}
		copy := *record
		copy.Grant = slices.Clone(record.Grant)
		s.record = &copy
		s.secret = secret
	case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict, identity.CommitOutcomeUnknown, identity.CommitOutcomeInProgress:
		if record != nil {
			return IssuanceResult{}, ErrInvalid
		}
	default:
		return IssuanceResult{}, ErrInvalid
	}
	return IssuanceResult{state: s}, nil
}

// Reveal discloses only proven-committed, invocation-local original material.
// Status-only recovery and every unknown/noncommit path return no plaintext.
func (r IssuanceResult) Reveal() (string, error) {
	if r.state == nil || r.state.receipt.Outcome != identity.CommitOutcomeCommitted || r.state.secret.state == nil {
		return "", ErrDisclosure
	}
	return r.state.secret.Reveal()
}

// DeliveryOutcome reports the shared reveal observation without renewing it.
func (r IssuanceResult) DeliveryOutcome() IssuanceOutcome {
	if r.state == nil {
		return IssuanceUnspecified
	}
	switch r.state.receipt.Outcome {
	case identity.CommitOutcomeCommitted:
		if r.state.secret.state != nil && r.state.secret.state.revealed.Load() {
			return IssuanceCommittedAndRevealed
		}
		return IssuanceCommittedDeliveryUnknown
	case identity.CommitOutcomeNotCommitted, identity.CommitOutcomeConflict:
		return IssuanceNotCommitted
	default:
		return IssuanceCommitUnknown
	}
}

// Record returns a caller-owned safe record only when commit is proven.
func (r IssuanceResult) Record() (Record, bool) {
	if r.state == nil || r.state.record == nil || r.state.receipt.Outcome != identity.CommitOutcomeCommitted {
		return Record{}, false
	}
	copy := *r.state.record
	copy.Grant = slices.Clone(copy.Grant)
	return copy, true
}

// Receipt returns independently owned original coordinator metadata, including
// on unknown outcomes. It neither proves delivery nor grants current authority.
func (r IssuanceResult) Receipt() (identity.CommandResult, error) {
	if r.state == nil {
		return identity.CommandResult{}, ErrInvalid
	}
	copy := r.state.receipt
	feature := *copy.Feature
	copy.Feature = &feature
	return copy, nil
}

// Recovery preserves every exact original safe lookup dimension without a raw
// key, digest, fresh record or new command. Current disclosure authorization is
// still required by Service.Recover; this query alone grants no authority.
func (r IssuanceResult) Recovery() (identity.RecoveryQuery, error) {
	if r.state == nil {
		return identity.RecoveryQuery{}, ErrInvalid
	}
	b := r.state.receipt.Binding
	return identity.RecoveryQuery{CommandID: b.CommandID, TenantID: b.TenantID, UserID: b.UserID, AnonymousFlowID: b.AnonymousFlowID, ActorID: b.ActorID, ActorKind: b.ActorKind, OperationID: b.OperationID, RecordID: b.RecordID, LinkMode: b.LinkMode}, nil
}
func (IssuanceResult) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.IssuanceResult(redacted)")
}
func (IssuanceResult) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (IssuanceResult) MarshalText() ([]byte, error) { return nil, ErrDisclosure }
