package risk

import "context"

// PrepareUse resolves the exact original phone-evidence issuance through the
// configured native executor and authenticates its committed record for a
// distinct consuming command. Both requests must be trusted, immutable workflow
// input; the original must retain its issuance command, actor and complete scope.
// Native records remain private. No providers, counters or fresh issuance run.
//
// One bounded context covers resolution and local precheck. Cancellation retains
// its context error; unavailable outcomes, executor errors and panics are
// redacted. Every error returns zero proof. Original exclusive expiry and the
// precheck time are never renewed. The returned immutable proof grants no
// reservation, current-counter or protected-mutation authority; the sole durable
// coordinator must still establish those facts. Concurrent calls are safe when
// configured collaborators satisfy their own concurrency contracts.
func (s PhoneEvidenceIssuer) PrepareUse(ctx context.Context, original PhoneEvidenceRequest, consuming EvidenceUseRequest) (use EvidenceUse, err error) {
	defer func() {
		if recover() != nil {
			use, err = EvidenceUse{}, ErrEvidenceUnavailable
		}
	}()
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
	if !validEvidenceCommandID(consuming.CommandID) || consuming.CommandID == original.CommandID || !scopeID(consuming.Actor) || consuming.Recovery != original.Recovery {
		return EvidenceUse{}, ErrInvalidEvidenceExecution
	}
	if _, err := ParseRiskEvidenceRef(consuming.Reference.value); err != nil {
		return EvidenceUse{}, ErrInvalidEvidenceExecution
	}
	bounded, cancel := context.WithTimeout(ctx, s.state.timeout)
	defer cancel()
	resolved, resolveErr := s.state.executor.Resolve(bounded, intent)
	if err := bounded.Err(); err != nil {
		return EvidenceUse{}, err
	}
	afterResolve := s.state.clock()
	if resolveErr != nil || evaluationTime(afterResolve, start, start, s.state.timeout) != nil {
		return EvidenceUse{}, ErrEvidenceUnavailable
	}
	if resolved.state == nil || resolved.state.intent.state != intent.state {
		return EvidenceUse{}, ErrInvalidEvidenceExecution
	}
	if resolved.state.outcome != EvidenceCommitted {
		return EvidenceUse{}, ErrEvidenceUnavailable
	}
	use, err = s.PrecheckUse(bounded, original, consuming, resolved.state.record)
	if err != nil {
		return EvidenceUse{}, err
	}
	finish := s.state.clock()
	if err := bounded.Err(); err != nil {
		return EvidenceUse{}, err
	}
	// Precheck has its own local budget. It must not restart this operation's
	// total deadline or let a native resolution renew the original interval.
	if evaluationTime(finish, afterResolve, start, s.state.timeout) != nil || use.state.checkedAt.Before(afterResolve) || use.Validate(consuming, finish) != nil {
		return EvidenceUse{}, ErrEvidenceUnavailable
	}
	return use, nil
}
