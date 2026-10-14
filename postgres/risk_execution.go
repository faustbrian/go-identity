package postgres

import (
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// RiskExecutionContributor opts the exact durable owner into one-use domain
// execution. ValidateRiskEvidenceCommand is pure bounded native scope/policy
// authentication. CheckRiskEvidence rechecks the reserved original row, current
// authority, policy/provider versions, counters and exclusive expiry in the
// domain transaction, before mutation and again before finalization. Finalize
// must CAS the same reserved command/fingerprint/generation to terminal used
// after rechecking expiry; zero affected rows is failure. All phases must deny
// missing/mismatched/terminal rows, never issue, renew, release or run provider
// callbacks. No private transaction, retry, retained handle or closure is allowed.
// The feature owner separately checks current user/factor/domain authority.
// Reservation/release-only implementations remain closed to domain execution.
type RiskExecutionContributor interface {
	RiskReleaseContributor
	ValidateRiskEvidenceCommand(identity.Command, RiskEvidencePlan) error
	CheckRiskEvidence(context.Context, RiskApplyWork) error
	FinalizeRiskEvidence(context.Context, RiskFinalizeWork) error
}

type riskExecutionState struct {
	reservation riskReservationState
	command     identity.Command
	finalize    bool
}

func (s *riskExecutionState) usable(finalize bool) error {
	if s == nil || s.finalize != finalize || s.reservation.previousGeneration != 0 || s.reservation.releaseProof != 0 || s.reservation.usable() != nil || !s.reservation.coordinator.owns(s.reservation.work) || s.reservation.work.state.execution.reservation.plan != s.reservation.plan {
		return invalidWork()
	}
	return nil
}

func (s *riskExecutionState) binding(p RiskReservationContributor, finalize bool) (RiskReservationBinding, error) {
	if e := s.usable(finalize); e != nil {
		return RiskReservationBinding{}, e
	}
	return s.reservation.binding(p)
}

func (s *riskExecutionState) nativeCommand(p RiskReservationContributor, finalize bool) (identity.Command, error) {
	if _, e := s.binding(p, finalize); e != nil {
		return identity.Command{}, e
	}
	return s.command, nil
}

// RiskApplyWork grants invocation-only bounded primary reads and exact native
// input to the registered risk owner. It exposes no mutation or raw driver.
// Trusted read/locking SQL only; zero, foreign and retained handles fail. Copies
// share lifetime; serial use only, and rows must close before callback return.
type RiskApplyWork struct{ state *riskExecutionState }

// Format redacts command inputs and transaction custody for every format verb.
func (RiskApplyWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RiskApplyWork(redacted)"))
}

// MarshalJSON rejects serialization of invocation authority, including zero.
func (RiskApplyWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects serialization of invocation authority, including zero.
func (RiskApplyWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding returns exact current-generation custody; no takeover/release proof.
func (w RiskApplyWork) Binding(p RiskReservationContributor) (RiskReservationBinding, error) {
	return w.state.binding(p, false)
}

// NativeCommand returns immutable admitted input only to the exact owner.
func (w RiskApplyWork) NativeCommand(p RiskReservationContributor) (identity.Command, error) {
	return w.state.nativeCommand(p, false)
}

// Query reads bounded primary state without exposing transaction closure.
func (w RiskApplyWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if e := w.state.usable(false); e != nil {
		return nil, e
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// DatabaseTime samples primary time; it cannot renew original evidence or Work.
func (w RiskApplyWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if e := w.state.usable(false); e != nil {
		return time.Time{}, e
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

// RiskFinalizeWork grants invocation-only terminal mutation in the same domain
// transaction after current checks and provisional feature/audit/outbox effects.
// The exact owner must recheck expiry and CAS original custody. No resurrection,
// release or private commit is permitted. Copies share lifetime, serial use only;
// close rows before return. All effects remain provisional until coordinator commit.
type RiskFinalizeWork struct{ state *riskExecutionState }

// Format redacts command inputs and transaction custody for every format verb.
func (RiskFinalizeWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RiskFinalizeWork(redacted)"))
}

// MarshalJSON rejects serialization of terminal authority, including zero.
func (RiskFinalizeWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects serialization of terminal authority, including zero.
func (RiskFinalizeWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding returns original current-generation custody, not release authority.
func (w RiskFinalizeWork) Binding(p RiskReservationContributor) (RiskReservationBinding, error) {
	return w.state.binding(p, true)
}

// NativeCommand returns the same immutable admitted command to the exact owner.
func (w RiskFinalizeWork) NativeCommand(p RiskReservationContributor) (identity.Command, error) {
	return w.state.nativeCommand(p, true)
}

// Query returns bounded invocation-owned rows from the domain transaction.
func (w RiskFinalizeWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if e := w.state.usable(true); e != nil {
		return nil, e
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// Exec runs one bounded trusted terminal statement, not transaction closure.
func (w RiskFinalizeWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if e := w.state.usable(true); e != nil {
		return 0, e
	}
	return w.state.reservation.work.Exec(ctx, sql, args...)
}

// DatabaseTime samples primary time without renewing validity or Work lifetime.
func (w RiskFinalizeWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if e := w.state.usable(true); e != nil {
		return time.Time{}, e
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

func riskExecutionParticipant(p *admittedKernelPlan) RiskExecutionContributor {
	if p == nil || p.risk == nil {
		return nil
	}
	for _, entry := range p.contributors {
		if entry.descriptor.Owner == "identity/risk/postgres" {
			participant, ok := entry.contributor.(RiskExecutionContributor)
			if ok && !nilContributor(participant) && reflect.TypeOf(participant).Comparable() {
				return participant
			}
		}
	}
	return nil
}

func validateRiskExecution(participant RiskExecutionContributor, command identity.Command, plan RiskEvidencePlan) (err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	if e := participant.ValidateRiskEvidenceCommand(command, plan); e != nil {
		_, _, _, safe := abortClassification(e)
		return safe
	}
	return nil
}

func (c *Coordinator) runRiskExecution(ctx context.Context, w Work, command identity.Command, finalize bool) (err error) {
	p := w.state.execution.reservation.plan
	if p.risk == nil {
		return nil
	}
	participant := riskExecutionParticipant(p)
	if participant == nil {
		return w.fail(ctx, invalidPlan())
	}
	if e := validateRiskExecution(participant, command, *p.risk); e != nil {
		return w.fail(ctx, e)
	}
	s := &riskExecutionState{reservation: riskReservationState{coordinator: c, work: w, plan: p, active: true, contributor: participant}, command: command, finalize: finalize}
	defer func() {
		s.reservation.active = false
		s.command = identity.Command{}
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if e := s.usable(finalize); e != nil {
		return w.fail(ctx, e)
	}
	var e error
	if finalize {
		e = participant.FinalizeRiskEvidence(ctx, RiskFinalizeWork{state: s})
	} else {
		e = participant.CheckRiskEvidence(ctx, RiskApplyWork{state: s})
	}
	if e != nil {
		_, _, _, safe := abortClassification(e)
		return w.fail(ctx, safe)
	}
	if w.state.rows != nil || w.usable() != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	return nil
}
