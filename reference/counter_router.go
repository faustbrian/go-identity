package reference

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
)

// velocityCounterRouter is the reference-owned deferred connection. Pure
// construction may retain it before recovery; only RecoverVelocity can install
// an activated native owner. It does not create results, retry mutations, renew
// evidence or bypass the native owner's per-use eligibility checks.
type velocityCounterRouter struct{ state *storeState }

var _ risk.CounterStore = velocityCounterRouter{}

func (r velocityCounterRouter) Mutate(ctx context.Context, command risk.CounterCommand) (risk.CounterResult, error) {
	if ctx == nil || r.state == nil {
		return risk.CounterResult{}, risk.ErrInvalidCounterCommand
	}
	if err := ctx.Err(); err != nil {
		return risk.CounterResult{}, err
	}
	s := r.state
	if err := command.ValidateConfiguration(s.policy, s.keys); err != nil {
		return risk.CounterResult{}, err
	}
	tenant := command.Bindings().Tenant
	s.mu.Lock()
	t := s.tenants[tenant]
	if s.closed || t == nil || t.busy || t.counter == nil {
		s.mu.Unlock()
		return risk.CounterResult{}, identity.UnavailableError{}
	}
	store := t.counter
	if s.active == 0 {
		s.drained = make(chan struct{})
	}
	s.active++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		if s.active == 0 {
			close(s.drained)
		}
		s.mu.Unlock()
	}()
	bounded, cancel := context.WithTimeout(ctx, s.config.PrimaryTimeout)
	stop := context.AfterFunc(s.lifetime, cancel)
	defer stop()
	defer cancel()
	// Preserve committed/unknown declarations even if shutdown races the
	// result. Returning an invented empty noncommit would lose durable truth.
	result, err := store.Mutate(bounded, command)
	if bounded.Err() != nil {
		return result, bounded.Err()
	}
	return result, err
}
