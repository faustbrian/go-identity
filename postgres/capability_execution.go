package postgres

import (
	"context"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// CapabilityExecutionContributor supplies provisional consumption and terminal
// finalization in the sole coordinator's domain transaction. Apply must lock the
// exact reserved input, check exclusive primary expiry and increment only below
// its signed maximum. Finalize must recheck expiry and CAS that same current
// command/fingerprint/generation to finalized. Neither phase may issue, release,
// renew, retry, retain handles, invoke network callbacks or close a transaction.
// Success is participant evidence, not a committed command outcome. This seam
// alone does not activate Begin: the native domain owner must also be complete.
type CapabilityExecutionContributor interface {
	CapabilityReleaseContributor
	ApplyCapability(context.Context, CapabilityApplyWork) error
	FinalizeCapability(context.Context, CapabilityFinalizeWork) error
}

type capabilityExecutionState struct {
	reservation capabilityReservationState
	finalize    bool
}

func (s *capabilityExecutionState) usable(finalize bool) error {
	if s == nil || s.finalize != finalize || s.reservation.previousGeneration != 0 {
		return invalidWork()
	}
	if err := (CapabilityReservationWork{state: &s.reservation}).usable(); err != nil {
		return err
	}
	c, w := s.reservation.coordinator, s.reservation.work
	if !c.owns(w) || w.state.execution.reservation.plan != s.reservation.plan {
		return invalidWork()
	}
	return nil
}

func (s *capabilityExecutionState) binding(p CapabilityExecutionContributor, finalize bool) (CapabilityReservationBinding, error) {
	if err := s.usable(finalize); err != nil {
		return CapabilityReservationBinding{}, err
	}
	return (CapabilityReservationWork{state: &s.reservation}).Binding(p)
}

// CapabilityApplyWork is an invocation-only capability to consume an original
// reserved token provisionally. Zero, foreign, stale, wrong-phase and retained
// handles fail. Copies share lifetime; serial use only. All rows must close
// before return. There is no constructor, raw driver or transaction closure.
type CapabilityApplyWork struct{ state *capabilityExecutionState }

// Format redacts retained command, proof and transaction metadata.
func (CapabilityApplyWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CapabilityApplyWork(redacted)"))
}

// MarshalJSON rejects serialization of invocation authority.
func (CapabilityApplyWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit text and map-key disclosure.
func (CapabilityApplyWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding returns the frozen input and current generation to the exact owner.
func (w CapabilityApplyWork) Binding(p CapabilityExecutionContributor) (CapabilityReservationBinding, error) {
	return w.state.binding(p, false)
}

// Exec executes one bounded trusted provisional statement, never closure.
func (w CapabilityApplyWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.state.usable(false); err != nil {
		return 0, err
	}
	return w.state.reservation.work.Exec(ctx, sql, args...)
}

// Query returns bounded invocation-owned rows, which must be closed.
func (w CapabilityApplyWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.state.usable(false); err != nil {
		return nil, err
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// DatabaseTime samples primary time without renewing original expiry or Work.
func (w CapabilityApplyWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.state.usable(false); err != nil {
		return time.Time{}, err
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

// CapabilityFinalizeWork grants invocation-only terminal mutation in the same
// domain transaction. It is distinct from apply and noncommit release authority.
// Copies expire on callback return, including panic; use serially, close rows,
// and never retain the handle. Finalization remains provisional until commit.
type CapabilityFinalizeWork struct{ state *capabilityExecutionState }

// Format redacts retained command, proof and transaction metadata.
func (CapabilityFinalizeWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CapabilityFinalizeWork(redacted)"))
}

// MarshalJSON rejects serialization of terminal authority.
func (CapabilityFinalizeWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit text and map-key disclosure.
func (CapabilityFinalizeWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding returns exact original current-generation custody to its owner.
func (w CapabilityFinalizeWork) Binding(p CapabilityExecutionContributor) (CapabilityReservationBinding, error) {
	return w.state.binding(p, true)
}

// Exec executes one bounded trusted terminal statement, never closure.
func (w CapabilityFinalizeWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.state.usable(true); err != nil {
		return 0, err
	}
	return w.state.reservation.work.Exec(ctx, sql, args...)
}

// Query returns bounded invocation-owned rows, which must be closed.
func (w CapabilityFinalizeWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.state.usable(true); err != nil {
		return nil, err
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// DatabaseTime samples primary time without renewing original expiry or Work.
func (w CapabilityFinalizeWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.state.usable(true); err != nil {
		return time.Time{}, err
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

func (c *Coordinator) runCapabilityExecution(ctx context.Context, w Work, finalize bool) (err error) {
	if !c.owns(w) {
		return invalidWork()
	}
	if err = w.usable(); err != nil {
		return err
	}
	if ctx == nil {
		return w.fail(w.state.ctx, invalidWork())
	}
	if err = ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	plan := w.state.execution.reservation.plan
	if plan == nil || plan.capability == nil {
		return w.fail(ctx, invalidPlan())
	}
	var participant CapabilityExecutionContributor
	for _, entry := range plan.contributors {
		if entry.descriptor.Owner == "capability/postgres" {
			participant, _ = entry.contributor.(CapabilityExecutionContributor)
		}
	}
	if nilContributor(participant) {
		return w.fail(ctx, invalidPlan())
	}
	s := &capabilityExecutionState{reservation: capabilityReservationState{coordinator: c, work: w, plan: plan, active: true, contributor: participant}, finalize: finalize}
	defer func() {
		s.reservation.active = false
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if err = s.usable(finalize); err != nil {
		return w.fail(ctx, err)
	}
	if finalize {
		err = participant.FinalizeCapability(ctx, CapabilityFinalizeWork{state: s})
	} else {
		err = participant.ApplyCapability(ctx, CapabilityApplyWork{state: s})
	}
	if err != nil {
		_, _, _, safe := abortClassification(err)
		return w.fail(ctx, safe)
	}
	if err = ctx.Err(); err != nil {
		return w.fail(ctx, err)
	}
	if w.state.rows != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	return w.usable()
}
