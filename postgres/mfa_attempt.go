package postgres

import (
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// MFAAttemptDisposition is a provisional denial decision, never a successful
// factor proof. Unknown values abort; the coordinator owns the sole commit.
type MFAAttemptDisposition uint8

const (
	// MFAAttemptUnchanged rolls back all provisional effects. It grants no
	// authentication and permits no inference that the submitted code is valid.
	MFAAttemptUnchanged MFAAttemptDisposition = iota + 1
	// MFAAttemptDenied commits the native shared-budget charge together with
	// required denial audits and the original terminal command result.
	MFAAttemptDenied
)

// MFATOTPAttemptContributor owns counted wrong-code denial for the exact native
// TOTP completion operation. ValidateMFACompletion authenticates original opaque
// submission, continuation scope and server policy before any transaction.
// RecordMFATOTPAttemptDenial locks/rechecks current continuation, account and
// factor authority after the command journal, compares under bounded policy,
// and charges the shared budget once on denial. It must not consume a child,
// advance successful replay state, issue a session, mutate kernel tables, invoke
// external callbacks, retain Work or open/close transactions. Correct comparison
// returns Unchanged, not proof. Instances are comparable and concurrency-safe.
type MFATOTPAttemptContributor interface {
	MFACompletionContributor
	RecordMFATOTPAttemptDenial(context.Context, MFATOTPAttemptWork) (MFAAttemptDisposition, error)
}

// MFATOTPAttemptBinding contains immutable correlation, not factor authority.
type MFATOTPAttemptBinding struct {
	Command     identity.CommandBinding
	Plan        MFACompletionPlan
	Fingerprint [32]byte
	Generation  uint64
}

// Format redacts command and continuation correlation.
func (MFATOTPAttemptBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFATOTPAttemptBinding(redacted)"))
}

// MarshalJSON rejects implicit custody export.
func (MFATOTPAttemptBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit custody export.
func (MFATOTPAttemptBinding) MarshalText() ([]byte, error) { return nil, invalidWork() }

// MFATOTPAttemptWork exposes bounded SQL only during the exact native counted
// callback. Zero, foreign, returned and copied-after-return handles deny. Copies
// share cancellation, SQL/row budgets and lifetime; use serially and close rows.
// There is no general Work, transaction, reservation or session accessor.
type MFATOTPAttemptWork struct{ state *mfaAttemptState }
type mfaAttemptState struct {
	work    Work
	owner   MFATOTPAttemptContributor
	command identity.Command
	active  bool
}

// Format redacts callback authority and opaque input.
func (MFATOTPAttemptWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.MFATOTPAttemptWork(redacted)"))
}

// MarshalJSON rejects callback authority export.
func (MFATOTPAttemptWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects callback authority export.
func (MFATOTPAttemptWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (w MFATOTPAttemptWork) usable() error {
	s := w.state
	if s == nil || !s.active || s.work.state == nil || s.work.state.execution == nil {
		return invalidWork()
	}
	e := s.work.state.execution
	if e.coordinator == nil || !e.coordinator.owns(s.work) || e.reservation == nil || e.reservation.plan == nil || e.reservation.plan.otp != nil || e.reservation.plan.mfaCompletion == nil || e.reservation.plan.fingerprint == ([32]byte{}) || e.reservation.journal.generation == 0 || e.reservation.journal.previousGeneration != 0 || mfaAttemptOwner(e.reservation.plan) != s.owner {
		return invalidWork()
	}
	return s.work.usable()
}

// Binding requires live callback custody and the exact registered owner.
func (w MFATOTPAttemptWork) Binding(owner MFATOTPAttemptContributor) (MFATOTPAttemptBinding, error) {
	if w.usable() != nil || nilContributor(owner) || !reflect.TypeOf(owner).Comparable() || owner != w.state.owner {
		return MFATOTPAttemptBinding{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	return MFATOTPAttemptBinding{Command: r.plan.binding, Plan: *r.plan.mfaCompletion, Fingerprint: r.plan.fingerprint, Generation: r.journal.generation}, nil
}

// NativeCommand borrows original opaque custody only for this counted callback.
func (w MFATOTPAttemptWork) NativeCommand(owner MFATOTPAttemptContributor) (identity.Command, error) {
	if _, err := w.Binding(owner); err != nil {
		return identity.Command{}, err
	}
	return w.state.command, nil
}

// Exec executes bounded trusted factor/continuation SQL, not transaction closure.
func (w MFATOTPAttemptWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query lends bounded rows that must be closed before the callback returns.
func (w MFATOTPAttemptWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime samples primary UTC without extending original validity.
func (w MFATOTPAttemptWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func mfaAttemptOwner(p *admittedKernelPlan) MFATOTPAttemptContributor {
	if p == nil || p.feature == nil || p.feature.Operation.OperationID != "identity.mfa.totp-verify" || p.mfaCompletion == nil || p.otp != nil {
		return nil
	}
	for _, e := range p.contributors {
		if e.descriptor == p.feature.Contributor {
			owner, ok := e.contributor.(MFATOTPAttemptContributor)
			if ok && !nilContributor(owner) && reflect.TypeOf(owner).Comparable() {
				return owner
			}
		}
	}
	return nil
}

// PrepareMFATOTPAttemptPlan freezes the native completion declaration for the
// denial-only route. It performs no IO, comparison, reservation or consumption.
// The returned owned snapshot is not authority; ordinary opaque execution denies.
func (c *Coordinator) PrepareMFATOTPAttemptPlan(b identity.CommandBinding, command identity.Command, p CommandPlan) (CommandPlan, error) {
	_, snapshot, _, err := c.prepareMFATOTPAttempt(b, command, p)
	return snapshot, err
}

func (c *Coordinator) prepareMFATOTPAttempt(b identity.CommandBinding, command identity.Command, p CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	if c == nil || c.registry == nil || c.registry.state == nil || c.keys.current == 0 || p.OTP != nil || !validMFACompletionPlan(b, p) || p.Feature.Operation.OperationID != "identity.mfa.totp-verify" {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	s, ok := command.Feature()
	if _, opaque := command.OneTimeCode(); !ok || !opaque {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	q, snapshot, admitted, err := c.prepareFeature(b, command, s, p)
	if err != nil || mfaAttemptOwner(admitted) == nil {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	return q, snapshot, admitted, nil
}

// RecordMFATOTPAttemptDenial commits only native wrong-attempt accounting,
// denial audits and a stable aborted command, atomically in the existing journal
// transaction. Replay precedes comparison; changed input conflicts. Unchanged
// rolls back and returns Conflict, never successful authentication. Unresolved
// predecessors are not taken over or compared again. Commit ambiguity remains
// Unknown and requires observation of the original command, not replacement.
// No child/risk/OTP/session/domain reservation or lifecycle effect is invoked.
func (c *Coordinator) RecordMFATOTPAttemptDenial(ctx context.Context, b identity.CommandBinding, command identity.Command, p CommandPlan) (identity.CommandResult, error) {
	return c.recordCountedAttemptCommand(ctx, b, command, p, false, true)
}
