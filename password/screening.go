package password

import (
	"context"
	"slices"
	"time"

	"github.com/faustbrian/go-identity/risk"
	primitive "github.com/faustbrian/go-password"
)

// passwordScreening is frozen trusted service composition. collect is the
// owned provider orchestration closure, not request input or a policy override.
// It borrows the candidate synchronously, honors ctx, returns at most the
// configured mandatory signals, and must not retain custody or mutate returned
// facts concurrently. now must be a concurrency-safe trusted clock. No callback
// runs under a lock, Secret.Use, or transaction. Structural validation of facts
// establishes no provider provenance; concrete owned adapter wiring is required.
type passwordScreening struct {
	policy             risk.Policy
	now                func() time.Time
	collect            func(context.Context, risk.Context, primitive.Secret) ([]risk.Signal, error)
	protectedProviders bool
}

// newScreenedHash requires the risk owner's Allow decision for the explicitly
// selected complete or protected-provider lane. Every creating action must
// explicitly select HIBP; disabled or
// omitted provider policy is not an opt-out. Missing/unavailable facts retain
// the configured risk owner's fail-closed decision. Administrative/recovery
// actions use this same path. This result is not authorization, transactional
// evidence consumption, freshness renewal, or permission to persist a hash.
func (w passwordWork) newScreenedHash(ctx context.Context, secret primitive.Secret, s passwordScreening, binding risk.Context) (hash primitive.EncodedHash, assessment risk.Assessment, err error) {
	defer func() {
		if recover() != nil {
			hash = primitive.EncodedHash{}
			assessment = risk.Assessment{}
			err = ErrPasswordWork
		}
	}()
	if ctx == nil || !w.valid() || s.now == nil || s.collect == nil {
		return primitive.EncodedHash{}, risk.Assessment{}, ErrPasswordWork
	}
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return primitive.EncodedHash{}, risk.Assessment{}, err
	}
	started := s.now()
	binding.Now = started
	admission, err := s.admit(ctx, binding)
	if err != nil {
		return primitive.EncodedHash{}, risk.Assessment{}, err
	}
	var facts []risk.Signal
	last := started
	hash, err = w.newHash(ctx, secret, func(ctx context.Context, candidate primitive.Secret) error {
		collected, e := s.collect(ctx, binding, candidate)
		if e != nil || len(collected) > len(admission.Profile.RequiredSignals) {
			return ErrPasswordWork
		}
		facts = slices.Clone(collected)
		assessment, last, e = s.check(ctx, binding, last, facts)
		if e != nil || assessment.Decision.Action != risk.Allow {
			return ErrPasswordWork
		}
		return nil
	})
	if err != nil {
		return primitive.EncodedHash{}, assessment, err
	}
	// Cryptographic work may outlive a signal. Reassess the unchanged original
	// facts, never collect again or rewrite their age to extend validity.
	assessment, _, err = s.check(ctx, binding, last, facts)
	if err != nil || assessment.Decision.Action != risk.Allow {
		if err := ctx.Err(); err != nil {
			return primitive.EncodedHash{}, assessment, err
		}
		return primitive.EncodedHash{}, assessment, ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return primitive.EncodedHash{}, assessment, err
	}
	if err := w.admit(secret); err != nil {
		return primitive.EncodedHash{}, assessment, err
	}
	return hash, assessment, nil
}

// admit validates the selected phase before provider access. It retains context
// errors across each pure owner call; a concurrent cancellation is not an
// infrastructure failure and must not lose its standard error identity.
func (s passwordScreening) admit(ctx context.Context, binding risk.Context) (risk.Admission, error) {
	if _, err := s.policy.PasswordSignal(ctx, binding, risk.PasswordObservation{Failure: risk.ProviderUnavailable}); err != nil {
		if err := ctx.Err(); err != nil {
			return risk.Admission{}, err
		}
		return risk.Admission{}, ErrPasswordWork
	}
	admission, err := s.policy.Admit(binding.Operation)
	if err != nil {
		return risk.Admission{}, ErrPasswordWork
	}
	if s.protectedProviders {
		if _, err := s.policy.AssessProtectedProviders(ctx, binding, nil); err != nil {
			if err := ctx.Err(); err != nil {
				return risk.Admission{}, err
			}
			return risk.Admission{}, ErrPasswordWork
		}
	}
	return admission, nil
}

func (s passwordScreening) check(ctx context.Context, binding risk.Context, last time.Time, facts []risk.Signal) (risk.Assessment, time.Time, error) {
	now := s.now()
	if now.IsZero() || now.Before(last) {
		return risk.Assessment{}, time.Time{}, ErrPasswordWork
	}
	binding.Now = now
	if s.protectedProviders {
		providers, err := s.policy.AssessProtectedProviders(ctx, binding, facts)
		if err != nil {
			return risk.Assessment{}, time.Time{}, ErrPasswordWork
		}
		// This private summary never leaves through the complete Prepare API.
		return risk.Assessment{Decision: providers.Decision, PolicyVersion: providers.PolicyVersion, Signals: providers.Signals}, now, nil
	}
	assessment, err := s.policy.Assess(ctx, binding, facts)
	if err != nil {
		return risk.Assessment{}, time.Time{}, ErrPasswordWork
	}
	return assessment, now, nil
}
