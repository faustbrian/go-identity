package risk

import (
	"context"
	"errors"
)

// ErrInvalidProtectedProviderAdmission rejects absent, foreign, restrictive or
// expired provider-only evidence without exposing correlated observations.
var ErrInvalidProtectedProviderAdmission = errors.New("risk: invalid protected provider admission")

// EvaluateProtectedProviders collects the configured mandatory provider facts
// for CredentialMutation/ReserveWithCommand using Evaluate's bounded readers,
// failure policy and original freshness checks. Only velocity is deferred: no
// counter source/store or standalone decision-audit sink is invoked. Subject
// and Attribution must be empty; the protected coordinator owns counters and
// atomic audit. An Allow is provider preparation, never mutation permission.
// Other action classes and issuing phases deny before provider work.
func (e Evaluator) EvaluateProtectedProviders(ctx context.Context, request EvaluateRequest) (EvaluateResult, error) {
	return e.evaluate(ctx, request, true)
}

// RequireProtectedProviderAdmission rechecks an owned provider-only Allow from
// this exact Evaluator against its original tenant, operation and attempt.
// The configured clock checks original facts without rereading providers or
// renewing freshness. Public decisions, foreign evaluations and authentication
// evaluations cannot substitute for the private provenance. This concurrent-
// safe, IO-free check does not grant counter allowance or mutation authority:
// the owner must reserve native counters and audit atomically with its effects.
func (e Evaluator) RequireProtectedProviderAdmission(ctx context.Context, result EvaluateResult, scope Context) (err error) {
	if ctx == nil {
		return ErrInvalidContext
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	defer func() {
		if recover() != nil {
			err = ErrInvalidProtectedProviderAdmission
		}
	}()
	p := result.provenance
	if e.state == nil || p == nil || p.owner != e.state || !p.protectedProviders || result.counter != nil || result.assessment.Decision.Action != Allow || result.Decision != result.assessment.Decision || result.PolicyVersion != result.assessment.PolicyVersion {
		return ErrInvalidProtectedProviderAdmission
	}
	original := p.context
	if scope.Tenant != original.Tenant || scope.Operation != original.Operation || scope.Attempt != original.Attempt {
		return ErrInvalidProtectedProviderAdmission
	}
	now := e.state.clock()
	if !validTime(now) || now.Before(original.Now) {
		return ErrInvalidProtectedProviderAdmission
	}
	original.Now = now
	assessment, err := e.state.policy.AssessProtectedProviders(ctx, original, p.signals)
	if err != nil || assessment.Decision.Action != Allow {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ErrInvalidProtectedProviderAdmission
	}
	return ctx.Err()
}
