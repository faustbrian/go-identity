package risk

import (
	"context"
	"crypto/hmac"
	"fmt"
	"io"
	"time"
)

// EvidenceUseRequest is trusted protected-workflow input, not authorization.
// CommandID and Actor identify the later consuming command, separately from
// the issuance identity. Recovery must exactly match the original issued scope.
// Reference is the presented bearer. Never deserialize this value as trusted
// transport input. The coordinator still owns authorization and atomic use.
type EvidenceUseRequest struct {
	CommandID, Actor string
	Recovery         CarrierRequest
	Reference        RiskEvidenceRef
}

func (EvidenceUseRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvidenceUseRequest(redacted)")
}
func (EvidenceUseRequest) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (EvidenceUseRequest) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// EvidenceUse is an immutable, core-authenticated local precheck. It proves
// exact original intent, presented bearer integrity and a non-expanded original
// interval, and freezes a separate proposed consuming command. It proves no
// journal existence/state, current counters, reservation, consumption or
// authorization. Only the durable participant through the sole coordinator
// may establish those facts. Zero is invalid; copies are immutable and safe for
// concurrent reads. No method consumes, renews expiry or performs I/O.
type EvidenceUse struct{ state *evidenceUse }
type evidenceUse struct {
	request   EvidenceUseRequest
	intent    EvidenceIntent
	record    EvidenceRecord
	checkedAt time.Time
}

// ValidateUseConfiguration checks a native adapter's immutable startup custody
// against this issuer before installing RecheckUse. PolicyVersion must equal
// the issuer's risk/carrier policy; keys must equal its complete retained set,
// including both independent secret lanes. Order is irrelevant. Zero, missing,
// duplicate or foreign configuration returns redacted ErrInvalidPolicy.
// This bounded local comparison invokes no callbacks, clock, provider, store or
// cryptography; it retains no caller slice and grants no evidence-use authority.
// Configuration must not be modified concurrently with this call.
func (s PhoneEvidenceIssuer) ValidateUseConfiguration(policyVersion uint64, keys []EvidenceKey) error {
	if s.state == nil || policyVersion != s.state.evaluation.state.policy.state.version || len(keys) != len(s.state.keys) {
		return ErrInvalidPolicy
	}
	for _, expected := range s.state.keys {
		found := false
		for _, key := range keys {
			if key == expected {
				found = true
				break
			}
		}
		if !found {
			return ErrInvalidPolicy
		}
	}
	return nil
}

func (EvidenceUse) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "risk.EvidenceUse(redacted)")
}
func (EvidenceUse) MarshalJSON() ([]byte, error) { return nil, ErrSensitiveSerialization }
func (EvidenceUse) MarshalText() ([]byte, error) { return nil, ErrSensitiveSerialization }

// PrecheckUse authenticates a bounded native record under this issuer's exact
// original request and current policy/provider configuration. The record may
// come only from the owned native composition; its MAC is not durability proof.
// No executor, provider, factor or counter is called. Errors return zero proof
// and omit input. ctx is checked before and after bounded local cryptography;
// the trusted clock is sampled twice and may not move backward or renew expiry.
// Both original issuance and proposed consumer inputs must be immutable during
// this call. The consumer must be a distinct canonical command, not issuance.
func (s PhoneEvidenceIssuer) PrecheckUse(ctx context.Context, original PhoneEvidenceRequest, request EvidenceUseRequest, record EvidenceRecord) (EvidenceUse, error) {
	if ctx == nil || s.state == nil {
		return EvidenceUse{}, ErrInvalidEvidenceRequest
	}
	if err := ctx.Err(); err != nil {
		return EvidenceUse{}, err
	}
	start := s.state.clock()
	intent, err := s.intent(original, start)
	if err != nil {
		return EvidenceUse{}, err
	}
	if !validEvidenceCommandID(request.CommandID) || request.CommandID == original.CommandID || !scopeID(request.Actor) || request.Recovery != original.Recovery || !hmac.Equal([]byte(request.Reference.value), []byte(record.Reference.value)) || !validEvidenceRecord(intent, record) {
		return EvidenceUse{}, ErrInvalidEvidenceExecution
	}
	now := s.state.clock()
	if err := ctx.Err(); err != nil {
		return EvidenceUse{}, err
	}
	if evaluationTime(now, start, start, s.state.timeout) != nil || start.Before(record.IssuedAt) || !now.Before(record.ExpiresAt) {
		return EvidenceUse{}, ErrInvalidEvidenceExecution
	}
	return EvidenceUse{state: &evidenceUse{request: request, intent: intent, record: record, checkedAt: now}}, nil
}

// Validate checks exact proposed consumer identity/scope and exclusive original
// expiry at a trusted time. It grants no protected-mutation authority, performs
// no I/O, and never refreshes the stored check or evidence interval. Later
// durable apply must independently use primary time and authoritative state.
func (p EvidenceUse) Validate(request EvidenceUseRequest, now time.Time) error {
	if p.state == nil || !validTime(now) || request != p.state.request || now.Before(p.state.checkedAt) || !now.Before(p.state.record.ExpiresAt) {
		return ErrInvalidEvidenceExecution
	}
	return nil
}

// RecheckUse authenticates the signed consuming projection against the complete
// original trusted recovery and subject inputs under this issuer's current
// immutable policy/provider configuration. now must be supplied by the sole
// coordinator from primary database UTC time, with microsecond precision.
// This local check invokes no clock, provider, counter, executor or callback;
// retained keys are accepted only while the original interval remains valid.
// It preserves CheckedAt and expiry and grants no reservation, current-counter,
// authorization or mutation authority. The adapter must separately match the
// consuming command and authoritative reserved row in that same transaction.
// Inputs must not be mutated concurrently. Zero or mismatched input fails closed.
func (s PhoneEvidenceIssuer) RecheckUse(original PhoneEvidenceRequest, prepared PreparedEvidenceUse, now time.Time) (EvidenceUseClaim, error) {
	if !databaseEvidenceTime(now) {
		return EvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	intent, err := s.intent(original, now)
	if err != nil {
		return EvidenceUseClaim{}, ErrInvalidEvidenceExecution
	}
	for _, binding := range intent.Bindings() {
		if binding != prepared.Binding {
			continue
		}
		for _, key := range s.state.keys {
			if key.version != binding.KeyVersion {
				continue
			}
			claim, err := key.RestoreUse(prepared)
			if err != nil || claim.Validate(now) != nil {
				return EvidenceUseClaim{}, ErrInvalidEvidenceExecution
			}
			return claim, nil
		}
	}
	return EvidenceUseClaim{}, ErrInvalidEvidenceExecution
}
