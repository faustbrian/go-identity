package hibp

import (
	"context"
	"errors"

	"github.com/faustbrian/go-identity/risk"
)

// SignalProvider normalizes fully bound password checks into neutral risk
// facts. It does not select password acceptance or outage policy. Assess maps
// ReplayID exactly to risk attempt identity; it never caches derived signals.
type SignalProvider interface {
	Assess(context.Context, CheckRequest) (risk.Signal, error)
}

type signalProvider struct {
	client  *Client
	checker Checker
	policy  risk.Policy
}

// NewSignalProvider borrows the owned checker and its immutable clock/profile.
// It rejects a disabled policy or provider TTL mismatch before any network work.
// The caller retains Client shutdown ownership; no resource or goroutine is
// added. Assess is concurrent-safe under Client's documented clock contract.
func NewSignalProvider(client *Client, policy risk.Policy) (SignalProvider, error) {
	config, e := policy.HIBPConfiguration()
	if e != nil || client == nil || client.http == nil || config.CacheTTL != client.config.CacheTTL {
		return nil, ErrInvalidConfiguration
	}
	return &signalProvider{client: client, checker: client, policy: policy}, nil
}

func (p *signalProvider) Assess(ctx context.Context, request CheckRequest) (risk.Signal, error) {
	if p == nil || p.client == nil || p.checker == nil {
		return risk.Signal{}, ErrInvalidConfiguration
	}
	if ctx == nil || !request.valid(p.client.config.PolicyVersion) {
		return risk.Signal{}, &CheckError{Outcome: OutcomeUnavailable, Cause: ErrInvalidRequest}
	}
	if e := ctx.Err(); e != nil {
		return risk.Signal{}, &CheckError{Outcome: OutcomeCancelled, Cause: e}
	}
	now, valid := p.client.observe()
	if !valid {
		return risk.Signal{}, &CheckError{Outcome: OutcomeUnavailable, Cause: ErrProviderUnavailable}
	}
	binding := risk.Context{Tenant: string(request.TenantID), Operation: request.Action, Attempt: string(request.ReplayID), Now: now}
	if _, e := p.policy.PasswordSignal(ctx, binding, risk.PasswordObservation{Failure: risk.ProviderUnavailable}); e != nil {
		return risk.Signal{}, normalizationError(e)
	}
	result, readErr := p.checker.Check(ctx, request)
	if e := ctx.Err(); e != nil {
		return risk.Signal{}, &CheckError{Outcome: OutcomeCancelled, Cause: e}
	}
	now, valid = p.client.observe()
	if !valid {
		return risk.Signal{}, &CheckError{Outcome: OutcomeUnavailable, Cause: ErrProviderUnavailable}
	}
	binding.Now = now
	observation := risk.PasswordObservation{}
	cause := error(nil)
	if !sameBinding(request, result) {
		observation.Failure = risk.ProviderInvalidBinding
		cause = ErrInvalidRequest
	} else if readErr != nil {
		observation.Failure, cause = providerFailure(readErr)
	} else if (result.Outcome == OutcomeNoMatch && result.BreachCount == 0) || (result.Outcome == OutcomeMatch && result.BreachCount > 0 && result.BreachCount <= p.client.config.MaxBreachCount) {
		observation = risk.PasswordObservation{BreachCount: result.BreachCount, ObservedAt: result.CheckedAt, ValidUntil: result.ProviderValidUntil, CheckedAt: now}
	} else {
		observation.Failure = risk.ProviderInvalidBinding
		cause = ErrInvalidRequest
	}
	signal, e := p.policy.PasswordSignal(ctx, binding, observation)
	if e != nil {
		if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
			return risk.Signal{}, &CheckError{Outcome: OutcomeCancelled, Cause: e}
		}
		signal, e = p.policy.PasswordSignal(ctx, binding, risk.PasswordObservation{Failure: risk.ProviderInvalidBinding})
		cause = ErrInvalidRequest
		if e != nil {
			return risk.Signal{}, normalizationError(e)
		}
	}
	if cause != nil {
		_, safe := failure(CheckResult{}, cause)
		return signal, safe
	}
	return signal, nil
}

func normalizationError(e error) error {
	if errors.Is(e, context.Canceled) || errors.Is(e, context.DeadlineExceeded) {
		return &CheckError{Outcome: OutcomeCancelled, Cause: e}
	}
	return &CheckError{Outcome: OutcomeUnavailable, Cause: ErrInvalidRequest}
}

func sameBinding(request CheckRequest, result CheckResult) bool {
	return request.OperationID == result.OperationID && request.TenantID == result.TenantID && request.Action == result.Action && request.Purpose == result.Purpose && request.SubjectScope == result.SubjectScope && request.PolicyVersion == result.PolicyVersion && request.ReplayID == result.ReplayID
}

func providerFailure(e error) (risk.ProviderFailure, error) {
	switch {
	case errors.Is(e, ErrMalformedRange):
		return risk.ProviderMalformed, ErrMalformedRange
	case errors.Is(e, ErrInvalidConfiguration):
		return risk.ProviderInvalidConfiguration, ErrInvalidConfiguration
	case errors.Is(e, ErrInvalidRequest):
		return risk.ProviderInvalidBinding, ErrInvalidRequest
	case errors.Is(e, ErrOverloaded):
		return risk.ProviderOverloaded, ErrOverloaded
	case errors.Is(e, ErrClosed):
		return risk.ProviderClosed, ErrClosed
	case errors.Is(e, context.Canceled):
		return risk.ProviderCancelled, context.Canceled
	case errors.Is(e, context.DeadlineExceeded):
		return risk.ProviderCancelled, context.DeadlineExceeded
	default:
		return risk.ProviderUnavailable, ErrProviderUnavailable
	}
}

var _ SignalProvider = (*signalProvider)(nil)
