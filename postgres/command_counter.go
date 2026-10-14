package postgres

import (
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// CommandCounterPlan freezes the core's keyed complete protected counter scope.
// Fingerprint binds tenant, operation, attempt, phase, current policy bounds,
// dimensions and retained digest aliases. It is a declaration, not authority;
// the registered native participant must reconstruct every input from the exact
// native command and current configuration. No raw dimensions or keys persist.
// Copies own scalars. Zero is invalid; concurrent input mutation is forbidden.
type CommandCounterPlan struct {
	PolicyVersion uint64
	Fingerprint   [32]byte
}

// Format redacts scoped fingerprints from diagnostics.
func (CommandCounterPlan) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CommandCounterPlan(redacted)"))
}

// MarshalJSON rejects export of private scope metadata.
func (CommandCounterPlan) MarshalJSON() ([]byte, error) { return nil, invalidPlan() }

// MarshalText rejects export of private scope metadata.
func (CommandCounterPlan) MarshalText() ([]byte, error) { return nil, invalidPlan() }
func encodeCommandCounterPlan(p CommandCounterPlan) []byte {
	return cborMap(map[string][]byte{"policy_version": cborUint(p.PolicyVersion), "fingerprint": cborBytes(p.Fingerprint[:])})
}

// CommandCounterDisposition is a provisional native reservation-phase decision.
// It never means the charge or protected domain mutation has committed.
type CommandCounterDisposition uint8

const (
	// CommandCounterAllowed permits the pending reservation to commit.
	CommandCounterAllowed CommandCounterDisposition = iota + 1
	// CommandCounterDenied commits the attempt with a denied audit/aborted receipt.
	CommandCounterDenied
)

// CommandCounterContributor is the sole native protected-counter participant.
// Pure validation must reconstruct the complete trusted native scope and current
// core policy before SQL. ReserveCommandCounters increments once on first owner,
// records its original snapshot, and reuses that snapshot on exact takeover.
// Denial is a disposition, not an error: returning an error rolls back the unit.
// No private transactions, provider/caller callbacks, closure or retained handles
// are allowed. SQL is provisional; only coordinator commit establishes outcome.
// Recovery must validate the original charge as prerequisite evidence, never
// report a charged reservation as proof of domain commitment. Instances must be
// comparable and support concurrent independent serial-use invocations.
type CommandCounterContributor interface {
	Contributor
	ValidateCommandCounters(identity.Command, CommandCounterPlan) error
	ReserveCommandCounters(context.Context, CommandCounterWork) (CommandCounterDisposition, error)
}

func commandCounterParticipant(p Contributor) (CommandCounterContributor, bool) {
	participant, ok := p.(CommandCounterContributor)
	return participant, ok && !nilContributor(participant) && reflect.TypeOf(participant).Comparable()
}

// CommandCounterBinding exposes only frozen charge linkage during recovery.
// A matching charge is prerequisite evidence, never proof of domain commit.
func (w RecoveryWork) CommandCounterBinding(p CommandCounterContributor) (CommandCounterBinding, error) {
	if w.usable() != nil || w.state.plan.counters == nil || w.state.entry.descriptor.Owner != "identity/risk/postgres" || nilContributor(p) || !reflect.TypeOf(p).Comparable() || w.state.entry.contributor != p || w.state.work.state.execution == nil || w.state.work.state.execution.reservation == nil {
		return CommandCounterBinding{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	return CommandCounterBinding{Command: w.state.plan.binding, Plan: *w.state.plan.counters, Fingerprint: w.state.plan.fingerprint, Generation: r.journal.generation, PreviousGeneration: r.journal.previousGeneration}, nil
}

func validateCommandCounters(p CommandCounterContributor, command identity.Command, plan CommandCounterPlan) (err error) {
	defer func() {
		if recover() != nil {
			err = invalidPlan()
		}
	}()
	if p.ValidateCommandCounters(command, plan) != nil {
		return invalidPlan()
	}
	return nil
}

// CommandCounterBinding supplies exact frozen scope and primary command ownership
// to the registered native participant. PreviousGeneration zero means first
// owner; a positive exact predecessor means reuse the recorded attempt, never
// increment again. Metadata alone grants no SQL authority or current allowance.
type CommandCounterBinding struct {
	Command                        identity.CommandBinding
	Plan                           CommandCounterPlan
	Fingerprint                    [32]byte
	Generation, PreviousGeneration uint64
}

// Format redacts command and charge linkage from diagnostics.
func (CommandCounterBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CommandCounterBinding(redacted)"))
}

// MarshalJSON rejects export of private charge linkage.
func (CommandCounterBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects export of private charge linkage.
func (CommandCounterBinding) MarshalText() ([]byte, error) { return nil, invalidWork() }

// CommandCounterWork is invocation-only coordinator SQL authority. Zero and
// foreign instances fail. Copies share lifetime; serial use only, close rows
// before return. It exposes no raw transaction, constructor or closure API.
// NativeCommand returns trusted native input only to the exact registered
// participant, never into the frozen plan, journal columns or diagnostics.
type CommandCounterWork struct{ state *commandCounterState }
type commandCounterState struct {
	work        Work
	participant CommandCounterContributor
	command     identity.Command
	active      bool
}

// Format redacts invocation state and private native command input.
func (CommandCounterWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CommandCounterWork(redacted)"))
}

// MarshalJSON rejects serialization of transaction authority.
func (CommandCounterWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects serialization of transaction authority.
func (CommandCounterWork) MarshalText() ([]byte, error) { return nil, invalidWork() }
func (w CommandCounterWork) usable() error {
	s := w.state
	if s == nil || !s.active || s.work.state == nil || s.work.state.execution == nil {
		return invalidWork()
	}
	c := s.work.state.execution.coordinator
	if !c.owns(s.work) || s.work.state.execution.reservation.plan.counters == nil {
		return invalidWork()
	}
	return s.work.usable()
}

// Binding validates exact-instance ownership and returns an owned scalar scope.
func (w CommandCounterWork) Binding(p CommandCounterContributor) (CommandCounterBinding, error) {
	if w.usable() != nil || nilContributor(p) || !reflect.TypeOf(p).Comparable() || p != w.state.participant {
		return CommandCounterBinding{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	return CommandCounterBinding{Command: r.plan.binding, Plan: *r.plan.counters, Fingerprint: r.plan.fingerprint, Generation: r.journal.generation, PreviousGeneration: r.journal.previousGeneration}, nil
}

// NativeCommand returns the immutable original admitted command to this owner.
func (w CommandCounterWork) NativeCommand(p CommandCounterContributor) (identity.Command, error) {
	if _, err := w.Binding(p); err != nil {
		return identity.Command{}, err
	}
	return w.state.command, nil
}

// MFACompletionScope lends the exact frozen anonymous TOTP/OTP/recovery completion subject
// and child plan only to the registered counter owner. It grants no factor or
// consumption authority; its purpose is to prevent a caller-selected counter
// subject or fictitious session. Zero, other profiles and foreign custody deny.
func (w CommandCounterWork) MFACompletionScope(owner CommandCounterContributor) (CapabilityPlan, MFACompletionPlan, error) {
	if _, err := w.Binding(owner); err != nil {
		return CapabilityPlan{}, MFACompletionPlan{}, err
	}
	p := w.state.work.state.execution.reservation.plan
	if p.feature == nil || p.feature.Operation.OperationID != "identity.mfa.totp-verify" && p.feature.Operation.OperationID != "identity.mfa.otp-verify" && p.feature.Operation.OperationID != "identity.mfa.recovery-use" || !validMFACompletionPlan(p.binding, p.snapshot()) {
		return CapabilityPlan{}, MFACompletionPlan{}, invalidWork()
	}
	return *p.capability, *p.mfaCompletion, nil
}

// Exec executes one bounded trusted statement, never transaction closure.
func (w CommandCounterWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query returns invocation-owned rows that must close before return.
func (w CommandCounterWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime reads primary UTC after locks without renewing ownership.
func (w CommandCounterWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func (c *Coordinator) reserveCommandCounters(ctx context.Context, tx pgx.Tx, command identity.Command, q claimRequest, p *admittedKernelPlan, j journalReservation, owner [16]byte) (denied bool, err error) {
	if p.counters == nil {
		return false, nil
	}
	var participant CommandCounterContributor
	for _, entry := range p.contributors {
		if entry.descriptor.Owner == "identity/risk/postgres" {
			participant, _ = entry.contributor.(CommandCounterContributor)
		}
	}
	if nilContributor(participant) || !reflect.TypeOf(participant).Comparable() {
		return false, invalidPlan()
	}
	fence, err := beginJournal(ctx, tx, q, c.keys, j, owner)
	if err != nil {
		return false, err
	}
	work, err := newWork(ctx, tx, p.binding, q, fence)
	if err != nil {
		return false, err
	}
	work.state.registry = c.registry.state
	r := &reservationState{coordinator: c, request: q, plan: p, journal: j, owner: owner}
	work.state.execution = &domainExecution{coordinator: c, reservation: r, ctx: ctx}
	defer func() {
		invalidateWork(work)
		if recover() != nil {
			denied = false
			err = identity.UnavailableError{}
		}
	}()
	if err = p.bindWork(work); err != nil {
		return false, err
	}
	if err = configureKernelWork(ctx, work); err != nil {
		return false, err
	}
	choice, err := c.reserveCounterInWork(ctx, work, participant, command)
	if err != nil {
		return false, identity.UnavailableError{}
	}
	if work.state.rows != nil || work.usable() != nil || choice != CommandCounterAllowed && choice != CommandCounterDenied {
		return false, invalidWork()
	}
	if choice == CommandCounterAllowed {
		return false, nil
	}
	now, err := work.DatabaseTime(ctx)
	if err != nil {
		return false, err
	}
	records, err := featureMutationAudits(ctx, p, now, "denied")
	if err != nil {
		return false, err
	}
	for i, record := range records {
		if err = work.StageAudit(p.audits[i].EventIndex, record); err != nil {
			return false, err
		}
	}
	if err = c.persistAuditPhase(work); err != nil {
		return false, identity.UnavailableError{}
	}
	if work.state.rows != nil || work.usable() != nil {
		return false, invalidWork()
	}
	result := featureOutcome(p.binding, &p.feature.Operation, identity.CommitOutcomeNotCommitted, 0)
	if err = terminalizeJournal(ctx, tx, q, j, owner, result, "denied"); err != nil {
		return false, err
	}
	return true, nil
}

// Both ordinary reservation and native counted MFA callbacks use the same
// participant and original transaction; this helper never opens or closes one.
func (c *Coordinator) reserveCounterInWork(ctx context.Context, work Work, participant CommandCounterContributor, command identity.Command) (choice CommandCounterDisposition, err error) {
	state := &commandCounterState{work: work, participant: participant, command: command, active: true}
	defer func() {
		state.active, state.command = false, identity.Command{}
		if recover() != nil {
			choice, err = 0, identity.UnavailableError{}
		}
	}()
	choice, err = participant.ReserveCommandCounters(ctx, CommandCounterWork{state: state})
	if err != nil {
		return 0, identity.UnavailableError{}
	}
	if work.state.rows != nil || work.usable() != nil || choice != CommandCounterAllowed && choice != CommandCounterDenied {
		return 0, invalidWork()
	}
	return choice, nil
}
