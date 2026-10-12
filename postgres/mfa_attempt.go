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
	work               Work
	owner              MFATOTPAttemptContributor
	command            identity.Command
	active             bool
	counterCalled      bool
	counterDisposition CommandCounterDisposition
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

// ReserveCommandCounters invokes the exact registered protected-risk owner
// once inside this counted attempt transaction, after native browser/current
// authority admission and before factor comparison. Denied must return native
// MFAAttemptDenied without comparing a code. Wrong-code denial commits risk,
// budget and audit together; correct-code Unchanged rolls all of them back.
// No child, session, lifecycle or private transaction is invoked here.
func (w MFATOTPAttemptWork) ReserveCommandCounters(ctx context.Context, owner MFATOTPAttemptContributor) (CommandCounterDisposition, error) {
	if _, err := w.Binding(owner); err != nil {
		return 0, err
	}
	native := w.state.work
	if ctx == nil {
		return 0, native.fail(native.state.ctx, invalidWork())
	}
	if w.state.counterCalled {
		return 0, native.fail(ctx, invalidWork())
	}
	p := native.state.execution.reservation.plan
	participant := counterAdmissionParticipant(p)
	if participant == nil {
		return 0, native.fail(ctx, invalidPlan())
	}
	w.state.counterCalled = true
	choice, err := native.state.execution.coordinator.reserveCounterInWork(ctx, native, participant, w.state.command)
	if err != nil {
		return 0, native.fail(ctx, err)
	}
	w.state.counterDisposition = choice
	return choice, nil
}

// RequireActiveDirectoryAuthority fences the original pre-decision global and
// tenant epochs during the exact native counted callback, before factor locks.
// It does not disclose general Work or refresh authority. Live failures poison
// the sole transaction even if ignored; zero/foreign/returned custody denies.
func (w MFATOTPAttemptWork) RequireActiveDirectoryAuthority(ctx context.Context, owner MFATOTPAttemptContributor, expected DirectoryAuthorityAdmission) error {
	if err := w.usable(); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	native, command, err := otpAuthorityScope(ctx, w.state.work, b.Command, err)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, native, native.requireActiveDirectoryAuthority(ctx, command, expected))
}

// RequireRecipient fences the original selected user/identifier and security
// epochs during counted denial, using the same directory owner as successful
// completion. Take this before factor locks. It neither authenticates a code
// nor permits a session; live denied checks poison the transaction.
func (w MFATOTPAttemptWork) RequireRecipient(ctx context.Context, owner MFATOTPAttemptContributor, expected RecipientRecord) error {
	if err := w.usable(); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	native, command, err := otpAuthorityScope(ctx, w.state.work, b.Command, err)
	if err != nil {
		return err
	}
	return otpAuthorityFailure(ctx, native, native.requireRecipient(ctx, command, expected))
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
// A declared protected-risk charge uses the exact native counted callback and
// shares its transaction; omission or ignored risk denial aborts. Correct-code
// Unchanged rolls that provisional charge back with the callback. No child,
// OTP, session/domain reservation or lifecycle effect is invoked.
func (c *Coordinator) RecordMFATOTPAttemptDenial(ctx context.Context, b identity.CommandBinding, command identity.Command, p CommandPlan) (identity.CommandResult, error) {
	return c.recordCountedAttemptCommand(ctx, b, command, p, false, true, nil)
}

// RecordMFATOTPAttemptDenialWithOriginal charges the same native atomic denial
// lane using the original submitted claim and separately validated native
// counter-enriched command. Exact history remains original-input keyed; changed
// declarations still conflict and correct-code probing still rolls back.
func (c *Coordinator) RecordMFATOTPAttemptDenialWithOriginal(ctx context.Context, original, prepared identity.Command, p CommandPlan) (identity.CommandResult, error) {
	f, ok := prepared.Feature()
	if !ok {
		return identity.CommandResult{}, invalidPlan()
	}
	return c.recordCountedAttemptCommand(ctx, f.Binding, prepared, p, false, true, &original)
}
