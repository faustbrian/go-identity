package postgres

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// OTPReservationContributor owns counted correct verification and exact
// predecessor transfer in the sole coordinator's reservation transaction.
// ReserveOTP locks the declared issued challenge after the command, verifies
// current purpose/subject/channel/workflow/authorization, exclusive database
// expiry, expected version and digest-key version, then compares the opaque code
// once under the native bounded attempt policy. It binds the server attempt,
// complete command fingerprint, generation and target versions atomically.
// Wrong-code charges use RecordOTPAttemptDenial, not this rollback path.
// RebindOTP authenticates the original submission but never compares again;
// it CASes the exact prior reserved generation and complete original linkage.
// Missing, terminal, expired or mismatched rows deny without partial transfer.
// Neither method consumes, releases, renews validity, invokes network/provider
// callbacks, opens transactions, closes Work or retains any handle. Instances
// are comparable and concurrency-safe; handles are serial callback-only SQL.
// This phase set alone does not enable Begin or domain/recovery release.
type OTPReservationContributor interface {
	OTPAttemptContributor
	ReserveOTP(context.Context, OTPReservationWork) error
	RebindOTP(context.Context, OTPReservationWork) error
}

// OTPReservationBinding is private frozen correlation, not verification or
// commitment proof. Positive Generation is the current owner; PreviousGeneration
// is zero for initial reserve or the exact predecessor for a successor CAS.
type OTPReservationBinding struct {
	Command                        identity.CommandBinding
	Plan                           OTPAttemptPlan
	Fingerprint                    [32]byte
	Generation, PreviousGeneration uint64
}

// Format hides attempt and command linkage.
func (OTPReservationBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPReservationBinding(redacted)"))
}

// MarshalJSON denies private custody export.
func (OTPReservationBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText denies implicit private custody export.
func (OTPReservationBinding) MarshalText() ([]byte, error) { return nil, invalidWork() }

// OTPReservationWork grants bounded SQL to one exact enlisted OTP owner during
// reserve/rebind. Zero, foreign and returned handles deny. Copies share callback
// lifetime, context and row/SQL budgets, with no driver, transaction closure or
// ordinary Work accessor. Close rows before returning; use serially.
type OTPReservationWork struct{ state *otpReservationState }
type otpReservationState struct {
	coordinator *Coordinator
	work        Work
	plan        *admittedKernelPlan
	command     identity.Command
	previous    uint64
	owner       OTPReservationContributor
	active      bool
}

// Format hides invocation authority and code custody.
func (OTPReservationWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPReservationWork(redacted)"))
}

// MarshalJSON rejects invocation serialization.
func (OTPReservationWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects invocation serialization.
func (OTPReservationWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (w OTPReservationWork) usable() error {
	s := w.state
	if s == nil || !s.active || s.coordinator == nil || s.plan == nil || s.plan.otp == nil || s.plan.otp.Mode != OTPConsume || s.plan.feature == nil || s.work.state == nil || s.plan.belongsTo(s.coordinator.registry) != nil || s.work.state.registry != s.plan.registry || s.work.state.binding != s.plan.binding || s.plan.fingerprint == ([32]byte{}) || s.work.state.generation == 0 || s.previous != 0 && (s.previous == ^uint64(0) || s.work.state.generation != s.previous+1) {
		return invalidWork()
	}
	return s.work.usable()
}

// Binding requires live callback lifetime and exact registered instance.
func (w OTPReservationWork) Binding(owner OTPReservationContributor) (OTPReservationBinding, error) {
	if w.usable() != nil || nilContributor(owner) || !reflect.TypeOf(owner).Comparable() || owner != w.state.owner {
		return OTPReservationBinding{}, invalidWork()
	}
	s := w.state
	return OTPReservationBinding{Command: s.plan.binding, Plan: *s.plan.otp, Fingerprint: s.plan.fingerprint, Generation: s.work.state.generation, PreviousGeneration: s.previous}, nil
}

// NativeCommand lends the original immutable opaque submission to that owner
// only. Reserve may compare once; rebind must not compare or meter it again.
func (w OTPReservationWork) NativeCommand(owner OTPReservationContributor) (identity.Command, error) {
	if _, err := w.Binding(owner); err != nil {
		return identity.Command{}, err
	}
	return w.state.command, nil
}

// Exec executes bounded trusted challenge SQL, never transaction closure.
func (w OTPReservationWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query returns bounded rows that must be closed before callback return.
func (w OTPReservationWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime samples primary UTC; it does not renew challenge or owner expiry.
func (w OTPReservationWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func otpReservationOwner(p *admittedKernelPlan) OTPReservationContributor {
	owner, ok := otpAttemptOwner(p).(OTPReservationContributor)
	if !ok || nilContributor(owner) || !reflect.TypeOf(owner).Comparable() {
		return nil
	}
	return owner
}

// PrepareOTPReservationPlan freezes a consuming declaration after pure native
// validation, with no IO or authority. Denial-only owners and OTPCheck fail.
// Ordinary PrepareCommandPlan remains closed to opaque submissions. Returned
// custody is copied; callers must not mutate supplied plans concurrently.
func (c *Coordinator) PrepareOTPReservationPlan(b identity.CommandBinding, command identity.Command, p CommandPlan) (CommandPlan, error) {
	_, snapshot, _, err := c.prepareOTPReservation(b, command, p)
	return snapshot, err
}
func (c *Coordinator) prepareOTPReservation(b identity.CommandBinding, command identity.Command, p CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	q, snapshot, admitted, err := c.prepareOTPAttempt(b, command, p)
	if err != nil || admitted == nil || admitted.otp.Mode != OTPConsume || otpReservationOwner(admitted) == nil {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	return q, snapshot, admitted, nil
}

// ReserveOTPCommand uses the existing command claim/journal transaction and
// ordered one-use participants to reserve or CAS-rebind the native challenge.
// Exact live/terminal replay does not compare or charge again. Changed intent
// conflicts before invocation. Every participant prefix rolls back on failure;
// commit-attempt failure returns Unknown with no ownership and must recover the
// original command/attempt. Returned reservation does not enable domain Begin
// until the complete native current/finalize/release protocol exists. No local
// retry, renewal or independent transaction is introduced; deadlines only narrow.
func (c *Coordinator) ReserveOTPCommand(ctx context.Context, b identity.CommandBinding, command identity.Command, p CommandPlan) (Reservation, identity.CommandResult, error) {
	if ctx == nil || authenticatedOperation(b) {
		return Reservation{}, identity.CommandResult{}, invalidPlan()
	}
	q, snapshot, admitted, err := c.prepareOTPReservation(b, command, p)
	if err != nil || snapshot.Digest != p.Digest {
		return Reservation{}, identity.CommandResult{}, invalidPlan()
	}
	return c.reservePreparedCommand(ctx, b, command, q, snapshot, admitted, nil)
}

func (c *Coordinator) reserveOTP(ctx context.Context, tx pgx.Tx, command identity.Command, q claimRequest, p *admittedKernelPlan, j journalReservation, owner [16]byte) (err error) {
	if p.otp == nil {
		return nil
	}
	participant := otpReservationOwner(p)
	if participant == nil || p.otp.Mode != OTPConsume || p.feature == nil || p.belongsTo(c.registry) != nil || j.disposition != journalOwned || !bytes.Equal(q.safeFields, commandSafeFields(p.binding, &p.feature.Operation)) {
		return invalidPlan()
	}
	if err := validateOTPAttempt(participant, command, *p.otp); err != nil {
		return err
	}
	fence, err := beginJournal(ctx, tx, q, c.keys, j, owner)
	if err != nil {
		return err
	}
	work, err := newWork(ctx, tx, p.binding, q, fence)
	if err != nil {
		return err
	}
	work.state.registry = c.registry.state
	s := &otpReservationState{coordinator: c, work: work, plan: p, command: command, previous: j.previousGeneration, owner: participant, active: true}
	defer func() {
		s.active = false
		s.command = identity.Command{}
		invalidateWork(work)
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	if err := p.bindWork(work); err != nil {
		return err
	}
	if err := configureKernelWork(ctx, work); err != nil {
		return err
	}
	if err := c.admitOTPFeatureInput(ctx, work, command, p); err != nil {
		return err
	}
	handle := OTPReservationWork{state: s}
	if _, err := handle.Binding(participant); err != nil {
		return err
	}
	if j.previousGeneration == 0 {
		err = participant.ReserveOTP(ctx, handle)
	} else {
		err = participant.RebindOTP(ctx, handle)
	}
	if err != nil {
		return work.fail(ctx, err)
	}
	if work.state.rows != nil {
		return identity.UnavailableError{}
	}
	if err := c.admitOTPFeatureInput(ctx, work, command, p); err != nil {
		return err
	}
	return work.usable()
}
