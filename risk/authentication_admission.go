package risk

import (
	"context"
	"errors"
)

// ErrInvalidAuthenticationAdmission rejects absent, foreign, unaudited,
// restrictive or expired Authentication-lane evaluation without exposing facts.
var ErrInvalidAuthenticationAdmission = errors.New("risk: invalid authentication admission")

// RequireAuthenticationAdmission validates an original counted, audited Allow
// from this exact Evaluator against the trusted operation, tenant, attempt and
// subject dimensions. Public decision fields, source-only evaluations and
// serialized results cannot supply admission. Caller time and factor flags are
// ignored; the configured clock rechecks the original facts with exclusive
// expiry. Copies cannot renew freshness or change the logical counter command.
//
// This concurrent-safe check performs no provider, store, audit or counter IO.
// It is only abuse admission, not authentication, current account authority,
// native-store health, one-use evidence or permission to execute a mutation.
// The owning workflow must independently recheck those applicable authorities
// and retain its existing atomic replay/transaction protocol. Nil context and
// invalid values fail closed; cancellation/deadline errors remain attributable.
func (e Evaluator) RequireAuthenticationAdmission(ctx context.Context, result EvaluateResult, scope Context, subject Subject) (err error) {
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Clock callbacks are trusted configuration, but a failed clock cannot grant
	// admission or leak diagnostics through this sensitive boundary.
	defer func() {
		if recover() != nil {
			err = ErrInvalidAuthenticationAdmission
		}
	}()
	p := result.provenance
	if e.state == nil || e.state.audit == nil || p == nil || p.owner != e.state || result.counter == nil || result.counter.Outcome != CounterCommitted || result.counter.result.state == nil || result.counter.Signal.State != SignalClean || result.assessment.Decision.Action != Allow || result.Decision != result.assessment.Decision || result.PolicyVersion != result.assessment.PolicyVersion {
		return ErrInvalidAuthenticationAdmission
	}
	original := p.context
	if scope.Tenant != original.Tenant || scope.Operation != original.Operation || scope.Attempt != original.Attempt {
		return ErrInvalidAuthenticationAdmission
	}
	admission, err := e.state.counters.admitScope(scope, BeforeCredential)
	if err != nil || admission.Profile.Class != Authentication || result.PolicyVersion != admission.PolicyVersion {
		return ErrInvalidAuthenticationAdmission
	}
	command, err := e.state.counters.prepareAdmitted(scope, subject, BeforeCredential, admission, original.Now)
	if err != nil || command.state.binding.Fingerprint != result.counter.result.state.fingerprint {
		return ErrInvalidAuthenticationAdmission
	}
	now := e.state.clock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validTime(now) || now.Before(original.Now) {
		return ErrInvalidAuthenticationAdmission
	}
	original.Now = now
	// Retain original owned factor facts, never request-selected overrides.
	assessment, err := e.state.policy.Assess(ctx, original, p.signals)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrInvalidAuthenticationAdmission
	}
	if assessment.Decision.Action != Allow {
		return ErrInvalidAuthenticationAdmission
	}
	return ctx.Err()
}
