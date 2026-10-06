package postgres

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/jackc/pgx/v5"
)

// OTPAttemptDisposition is a provisional denial-phase decision, never proof of
// successful verification or commitment. Unknown/zero values abort the unit.
type OTPAttemptDisposition uint8

const (
	// OTPAttemptUnchanged records no denial; all provisional SQL is rolled back.
	// It grants no reservation, allowance, authentication or reusable precheck.
	OTPAttemptUnchanged OTPAttemptDisposition = iota + 1
	// OTPAttemptDenied requires the native owner to persist one exact attempt
	// charge/result proposal. The coordinator commits it with the aborted command
	// and required audits. Cross-scope/unknown denials must not charge another row.
	OTPAttemptDenied
)

// OTPAttemptContributor owns the native pre-reservation wrong-code phase. Pure
// validation authenticates the complete server-issued attempt/command binding
// against retained keys and trusted configuration. RecordOTPAttemptDenial locks
// the exact challenge after the already locked command, checks current scope,
// authority, lockout, expiry and expected version, performs bounded comparison,
// and records exactly one wrong-attempt increment with exhaustion as required.
// It must retain server attempt ID and complete canonical fingerprint and reject
// changed-input re-entry without mutation. The coordinator handles command
// replay BEFORE invocation, and owns audits, terminal result and sole commit.
//
// Never reserve/finalize a challenge, modify command/audit tables, use private
// transactions, run provider/caller callbacks, retain handles or close Work.
// Instances must be comparable and concurrency-safe; each Work is serial-use.
// Correct checks and consuming use remain separate native phases.
type OTPAttemptContributor interface {
	RecoveryContributor
	ValidateOTPAttemptCommand(identity.Command, OTPAttemptPlan) error
	RecordOTPAttemptDenial(context.Context, OTPAttemptWork) (OTPAttemptDisposition, error)
}

// OTPAttemptBinding exposes exact frozen linkage and authoritative complete
// command fingerprint. Generation is positive and this denial phase permits
// only a first owner, never takeover of an unresolved one-time reservation.
// Copies are owned scalars, not authority, proof or public response data.
type OTPAttemptBinding struct {
	Command     identity.CommandBinding
	Plan        OTPAttemptPlan
	Fingerprint [32]byte
	Generation  uint64
}

// Format hides attempt/command linkage.
func (OTPAttemptBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPAttemptBinding(redacted)"))
}

// MarshalJSON denies export of private attempt custody.
func (OTPAttemptBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit conversion of private attempt custody.
func (OTPAttemptBinding) MarshalText() ([]byte, error) { return nil, invalidWork() }

// OTPAttemptWork grants bounded SQL only within one coordinator-owned denial
// callback. Zero, foreign and returned handles deny. Copies share cancellation,
// row/SQL budgets and callback lifetime. Close rows before return, use serially,
// and never treat database time as renewal. There is no driver, transaction,
// constructor, closure, reservation or general Work accessor.
type OTPAttemptWork struct{ state *otpAttemptState }
type otpAttemptState struct {
	work    Work
	owner   OTPAttemptContributor
	command identity.Command
	active  bool
}

// Format redacts invocation state and secret custody.
func (OTPAttemptWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPAttemptWork(redacted)"))
}

// MarshalJSON rejects serialization of invocation authority.
func (OTPAttemptWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects implicit serialization of invocation authority.
func (OTPAttemptWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (w OTPAttemptWork) usable() error {
	s := w.state
	if s == nil || !s.active || s.work.state == nil || s.work.state.execution == nil {
		return invalidWork()
	}
	e := s.work.state.execution
	if !e.coordinator.owns(s.work) || e.reservation.plan == nil || e.reservation.plan.otp == nil || e.reservation.plan.feature == nil || e.reservation.plan.fingerprint == ([32]byte{}) || e.reservation.journal.generation == 0 || e.reservation.journal.previousGeneration != 0 {
		return invalidWork()
	}
	return s.work.usable()
}

// Binding validates active lifetime and exact registered instance ownership.
func (w OTPAttemptWork) Binding(owner OTPAttemptContributor) (OTPAttemptBinding, error) {
	if w.usable() != nil || nilContributor(owner) || !reflect.TypeOf(owner).Comparable() || owner != w.state.owner {
		return OTPAttemptBinding{}, invalidWork()
	}
	r := w.state.work.state.execution.reservation
	return OTPAttemptBinding{Command: r.plan.binding, Plan: *r.plan.otp, Fingerprint: r.plan.fingerprint, Generation: r.journal.generation}, nil
}

// NativeCommand lends the original opaque submission only to this native owner
// for one counted locked comparison. Never persist or log it; discard copies.
func (w OTPAttemptWork) NativeCommand(owner OTPAttemptContributor) (identity.Command, error) {
	if _, err := w.Binding(owner); err != nil {
		return identity.Command{}, err
	}
	return w.state.command, nil
}

// Query returns bounded callback-owned rows; close them before return.
func (w OTPAttemptWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// Exec performs trusted attempt/challenge SQL, never transaction closure.
func (w OTPAttemptWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// DatabaseTime samples primary UTC without changing original validity.
func (w OTPAttemptWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func otpAttemptParticipant(p Contributor) (OTPAttemptContributor, bool) {
	owner, ok := p.(OTPAttemptContributor)
	return owner, ok && !nilContributor(owner) && reflect.TypeOf(owner).Comparable()
}

func otpAttemptOwner(p *admittedKernelPlan) OTPAttemptContributor {
	if p == nil || p.otp == nil {
		return nil
	}
	for _, e := range p.contributors {
		if e.descriptor == otpDescriptor() {
			owner, _ := otpAttemptParticipant(e.contributor)
			return owner
		}
	}
	return nil
}

func validateOTPAttempt(owner OTPAttemptContributor, command identity.Command, plan OTPAttemptPlan) (err error) {
	defer func() {
		if recover() != nil {
			err = invalidPlan()
		}
	}()
	if owner == nil || owner.ValidateOTPAttemptCommand(command, plan) != nil {
		return invalidPlan()
	}
	return nil
}

// PrepareOTPAttemptPlan freezes a native counted-denial declaration without
// IO or authority. Ordinary PrepareCommandPlan/ReserveCommand still reject OTP;
// this seam admits RecordOTPAttemptDenial, not domain work. Consuming reserve
// additionally requires PrepareOTPReservationPlan's complete reservation owner.
// Native configuration authenticates the complete immutable submission before
// any transaction. Returned projections are owned copies; do not mutate input
// concurrently. Digest is replaced by the authoritative current-key mapping.
func (c *Coordinator) PrepareOTPAttemptPlan(b identity.CommandBinding, command identity.Command, p CommandPlan) (CommandPlan, error) {
	_, snapshot, _, err := c.prepareOTPAttempt(b, command, p)
	return snapshot, err
}

func (c *Coordinator) prepareOTPAttempt(b identity.CommandBinding, command identity.Command, p CommandPlan) (claimRequest, CommandPlan, *admittedKernelPlan, error) {
	fail := func() (claimRequest, CommandPlan, *admittedKernelPlan, error) {
		return claimRequest{}, CommandPlan{}, nil, invalidPlan()
	}
	if c == nil || c.registry == nil || c.registry.state == nil || c.keys.current == 0 || p.OTP == nil || p.Delivery != nil || p.CapabilityIssuance != nil {
		return fail()
	}
	s, ok := command.Feature()
	if _, custody := command.OneTimeCode(); !ok || !custody {
		return fail()
	}
	q, snapshot, admitted, err := c.prepareFeature(b, command, s, p)
	if err != nil || admitted == nil || validateOTPAttempt(otpAttemptOwner(admitted), command, *admitted.otp) != nil {
		return fail()
	}
	return q, snapshot, admitted, nil
}

// RecordOTPAttemptDenial runs the narrow pre-reservation denial transaction.
// It locks the global command claim/journal before invoking the exact native OTP
// owner; no risk/CAPTCHA/capability/session/domain reservation is invoked. A
// committed wrong-attempt charge, exhaustion, required denial audits and stable
// aborted command result are atomic. Exact replay returns history without
// comparison or another charge; changed command/attempt/plan conflicts.
//
// OTPAttemptUnchanged rolls back all provisional SQL and returns Conflict,
// granting no successful check or consuming authority. Expired pending history
// remains Unknown, never takeover/recomparison. Any commit-attempt failure is
// Unknown and must recover the original command AND server attempt identity;
// do not prepare a replacement submission. Current QueryPolicy authorizes safe
// observation; full consuming reservation/recovery remains in development.
// Earlier deadlines win; no local retry, callbacks under caller control, secret
// disclosure or private transaction ownership are exposed.
func (c *Coordinator) RecordOTPAttemptDenial(ctx context.Context, b identity.CommandBinding, command identity.Command, p CommandPlan) (identity.CommandResult, error) {
	if ctx == nil {
		return identity.CommandResult{}, invalidPlan()
	}
	q, snapshot, _, err := c.prepareOTPAttempt(b, command, p)
	if err != nil || snapshot.Digest != p.Digest {
		return identity.CommandResult{}, invalidPlan()
	}
	bounded, cancel := context.WithTimeout(ctx, c.maximumDuration)
	defer cancel()
	if c.pool == nil || c.pool.Raw() == nil {
		return identity.CommandResult{}, coordinatorError()
	}
	var owner [16]byte
	if _, err := rand.Read(owner[:]); err != nil || owner == ([16]byte{}) {
		return identity.CommandResult{}, identity.UnavailableError{}
	}
	tx, err := c.pool.Raw().BeginTx(bounded, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return identity.CommandResult{}, readFailure(bounded, err)
	}
	fail := func(result identity.CommandResult, cause error) (identity.CommandResult, error) {
		_, result, err := c.failedReservation(tx, b, result, cause)
		return result, err
	}
	d, err := lockCommandClaim(bounded, tx, q, c.keys)
	if err != nil {
		return fail(identity.CommandResult{}, err)
	}
	if d == claimConflict {
		return fail(featureOutcome(b, q.feature, identity.CommitOutcomeConflict, 0), identity.ConflictError{})
	}
	j, err := reserveJournal(bounded, tx, q, d, owner, c.leaseDuration)
	if err != nil {
		return fail(identity.CommandResult{}, err)
	}
	admitted, err := c.freezePlan(bounded, tx, b, q, d, snapshot)
	if err != nil {
		result := identity.CommandResult{}
		var conflict identity.ConflictError
		if errors.As(err, &conflict) {
			result = featureOutcome(b, q.feature, identity.CommitOutcomeConflict, 0)
		}
		return fail(result, err)
	}
	if j.disposition == journalTerminal && j.result != nil {
		return fail(*j.result, nil)
	}
	if j.disposition == journalBusy {
		return fail(featureOutcome(b, q.feature, identity.CommitOutcomeInProgress, j.retryAfter), nil)
	}
	if j.previousGeneration != 0 {
		return fail(featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), identity.UnavailableError{})
	}
	denied, err := c.recordOTPDenial(bounded, tx, command, q, admitted, j, owner)
	if err != nil {
		return fail(identity.CommandResult{}, err)
	}
	if !denied {
		return fail(featureOutcome(b, q.feature, identity.CommitOutcomeConflict, 0), identity.ConflictError{})
	}
	if err := tx.Commit(bounded); err != nil {
		return featureOutcome(b, q.feature, identity.CommitOutcomeUnknown, 0), readFailure(bounded, err)
	}
	return featureOutcome(b, q.feature, identity.CommitOutcomeNotCommitted, 0), identity.ForbiddenError{}
}

func (c *Coordinator) recordOTPDenial(ctx context.Context, tx pgx.Tx, command identity.Command, q claimRequest, p *admittedKernelPlan, j journalReservation, owner [16]byte) (denied bool, err error) {
	participant := otpAttemptOwner(p)
	if participant == nil || p.belongsTo(c.registry) != nil || j.disposition != journalOwned || j.previousGeneration != 0 {
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
	s := &otpAttemptState{work: work, owner: participant, command: command, active: true}
	defer func() {
		s.active, s.command = false, identity.Command{}
		invalidateWork(work)
		if recover() != nil {
			denied, err = false, identity.UnavailableError{}
		}
	}()
	if err = p.bindWork(work); err != nil {
		return false, err
	}
	if err = configureKernelWork(ctx, work); err != nil {
		return false, err
	}
	choice, err := participant.RecordOTPAttemptDenial(ctx, OTPAttemptWork{state: s})
	if err != nil {
		return false, identity.UnavailableError{}
	}
	if work.state.rows != nil || work.usable() != nil || choice != OTPAttemptUnchanged && choice != OTPAttemptDenied {
		return false, invalidWork()
	}
	s.active = false
	if choice == OTPAttemptUnchanged {
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
	if err = c.persistAuditPhase(work); err != nil || work.state.rows != nil || work.usable() != nil {
		return false, identity.UnavailableError{}
	}
	result := featureOutcome(p.binding, &p.feature.Operation, identity.CommitOutcomeNotCommitted, 0)
	if err = terminalizeJournal(ctx, tx, q, j, owner, result, "denied"); err != nil {
		return false, err
	}
	return true, nil
}
