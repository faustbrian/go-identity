package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/risk/internal/velocity"
)

// OwnedJournal binds this recovery owner's concrete journal to one original
// activated primary receipt. The opaque output is passed to the owned native
// adapter factory; it exposes no effect methods or caller-supplied callbacks.
// Construction and every later admission recheck current primary eligibility.
// Tenant, policy and complete key custody are checked before journal IO.
// An acknowledged intent retains its exact receipt through terminal recording;
// retries read authenticated original history and never authorize redispatch.
// All primary transactions finish before native work. Configuration is immutable
// and concurrent-safe; the caller retains pool ownership. Invalid custody returns
// InvalidInputError; primary failures are redacted, and cancellation is preserved.
// This connection neither publishes native health nor renews original expiry.
// It retains the original native-confirmed activation chain internally, with
// eligibility issued from this same primary owner. Callers cannot substitute a
// separately selected chain or journal. One outer journal timeout bounds export.
func (r VelocityRecovery) OwnedJournal(ctx context.Context, healthy VelocityHealthy) (velocity.Journal, error) {
	if r.state == nil || healthy.state == nil || healthy.state.owner != r.state || healthy.state.activated.IsZero() || healthy.state.lease == nil || healthy.state.cut == nil || healthy.state.cut.lease != healthy.state.lease {
		return velocity.Journal{}, identity.InvalidInputError{Field: "velocity_journal"}
	}
	bounded, cancel, err := r.state.bounded(ctx)
	if err != nil {
		return velocity.Journal{}, err
	}
	defer cancel()
	chain := healthy.state.chain
	chain.Eligibility, err = r.OwnedEligibility(bounded, healthy, chain.Lease, chain.Closure, chain.Publication, chain.Confirmation, chain.Native)
	if err != nil {
		return velocity.Journal{}, err
	}
	j := VelocityJournal{state: r.state.journal}
	validate := func(c risk.CounterCommand) error {
		if c.ValidateConfiguration(j.state.policy, j.state.keys) != nil || c.Bindings().Tenant != healthy.state.lease.tenant {
			return risk.ErrInvalidCounterCommand
		}
		return nil
	}
	bound, err := velocity.BindJournal(j.state.replay.Namespace(), validate,
		func(checkCtx context.Context, _ risk.CounterCommand) error {
			return r.CheckHealthy(checkCtx, healthy)
		},
		func(recordCtx context.Context, c risk.CounterCommand) (velocity.Attempt, error) {
			a, err := j.RecordAttempt(recordCtx, c)
			if err != nil {
				return velocity.Attempt{}, err
			}
			return velocity.BindAttempt(c, func(resultCtx context.Context, result risk.CounterResult) error {
				outcome, snapshot, err := result.Declaration(c)
				if err != nil {
					return err
				}
				return j.RecordResult(resultCtx, a, outcome, snapshot)
			})
		}, j.ReadResult)
	if err != nil {
		return velocity.Journal{}, err
	}
	return velocity.BindCurrentJournal(bounded, bound, r.state.journalReader, r.state.nativeVerifier, chain)
}
