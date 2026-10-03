package postgres

import (
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// CommandCounterAdmissionContributor opts the exact native counter owner into
// protected domain execution. CheckCommandCounters must recheck original charge
// custody, current policy, freshness, authoritative counters and any selected
// lockout/override profile under the same domain transaction. It must not charge
// again, renew original evidence, run callbacks or open a private transaction.
// Nil success permits only this phase; it is not independent authorization or
// commitment. The feature owner separately checks current domain authority.
// Missing implementation leaves counter-bearing Begin unsupported.
type CommandCounterAdmissionContributor interface {
	CommandCounterContributor
	CheckCommandCounters(context.Context, CommandCounterAdmissionWork) error
}

// CommandCounterAdmissionWork is invocation-only current-check custody over the
// coordinator's domain transaction. It exposes bounded reads and primary time,
// no transaction, closure or increment API. Queries must be trusted read/locking
// statements, never mutations. Copies share lifetime, serial use only; close
// returned rows before return. Zero, foreign owners and retained handles fail.
type CommandCounterAdmissionWork struct{ state *commandCounterState }

// Format redacts native inputs and transactional custody.
func (CommandCounterAdmissionWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CommandCounterAdmissionWork(redacted)"))
}

// MarshalJSON rejects export of transaction authority.
func (CommandCounterAdmissionWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects export of transaction authority.
func (CommandCounterAdmissionWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding returns current-generation linkage, never predecessor transfer
// authority. A committed charge is a prerequisite, not domain commitment.
func (w CommandCounterAdmissionWork) Binding(p CommandCounterContributor) (CommandCounterBinding, error) {
	b, e := (CommandCounterWork{state: w.state}).Binding(p)
	if e == nil {
		b.PreviousGeneration = 0
	}
	return b, e
}

// NativeCommand returns the exact admitted immutable input only to this owner.
func (w CommandCounterAdmissionWork) NativeCommand(p CommandCounterContributor) (identity.Command, error) {
	return (CommandCounterWork{state: w.state}).NativeCommand(p)
}

// Query reads bounded current primary state in the domain transaction.
func (w CommandCounterAdmissionWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	return (CommandCounterWork{state: w.state}).Query(ctx, sql, args...)
}

// DatabaseTime samples primary time without renewing Work or original evidence.
func (w CommandCounterAdmissionWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	return (CommandCounterWork{state: w.state}).DatabaseTime(ctx)
}

func counterAdmissionParticipant(p *admittedKernelPlan) CommandCounterAdmissionContributor {
	if p == nil || p.counters == nil {
		return nil
	}
	for _, entry := range p.contributors {
		if entry.descriptor.Owner == "identity/risk/postgres" {
			participant, ok := entry.contributor.(CommandCounterAdmissionContributor)
			if ok && !nilContributor(participant) && reflect.TypeOf(participant).Comparable() {
				return participant
			}
		}
	}
	return nil
}

func (c *Coordinator) checkCommandCounters(ctx context.Context, w Work, command identity.Command) (err error) {
	p := w.state.execution.reservation.plan
	if p.counters == nil {
		return nil
	}
	participant := counterAdmissionParticipant(p)
	if participant == nil {
		return w.fail(ctx, invalidPlan())
	}
	if e := validateCommandCounters(participant, command, *p.counters); e != nil {
		return w.fail(ctx, e)
	}
	state := &commandCounterState{work: w, participant: participant, command: command, active: true}
	defer func() {
		state.active = false
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if e := participant.CheckCommandCounters(ctx, CommandCounterAdmissionWork{state: state}); e != nil {
		_, _, _, safe := abortClassification(e)
		return w.fail(ctx, safe)
	}
	if w.state.rows != nil || w.usable() != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	return nil
}
