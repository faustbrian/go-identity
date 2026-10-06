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

// CaptchaUseReservationContributor owns the native protected-use reservation
// phases, not issuance replay ownership. ValidateCaptchaUseCommand is pure,
// bounded authentication of complete immutable command custody against current
// configuration and exact declared original. Reserve locks an already-issued
// row and binds the consuming command/fingerprint/generation. Rebind CASes the
// exact positive predecessor to its successor. Both authenticate signed input,
// check original exclusive expiry after locking using primary time, and deny
// missing, terminal, mismatched or foreign rows. They cannot issue, renew,
// release or consume evidence, call providers, open private transactions,
// close or retain Work. Copies share callback lifetime; use each handle serially
// and close every row before return. Independent invocations may be concurrent.
// This interface alone does not enable domain execution or recovery release.
type CaptchaUseReservationContributor interface {
	RecoveryContributor
	ValidateCaptchaUseCommand(identity.Command, CaptchaEvidencePlan) error
	ReserveCaptchaEvidence(context.Context, CaptchaUseReservationWork) error
	RebindCaptchaEvidence(context.Context, CaptchaUseReservationWork) error
}

// CaptchaUseReservationBinding is an owned snapshot of the exact original and
// consuming command. Fingerprint is the coordinator's authoritative complete
// intent fingerprint, not the provider-token replay fingerprint. Generation is
// positive. PreviousGeneration is zero for first reservation, otherwise the
// exact predecessor. This metadata is neither authentication nor commit proof.
type CaptchaUseReservationBinding struct {
	Command                        identity.CommandBinding
	Plan                           CaptchaEvidencePlan
	Fingerprint                    [32]byte
	Generation, PreviousGeneration uint64
}

// Format redacts original and consuming linkage.
func (CaptchaUseReservationBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CaptchaUseReservationBinding(redacted)"))
}

// MarshalJSON denies private custody serialization.
func (CaptchaUseReservationBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText denies private custody serialization.
func (CaptchaUseReservationBinding) MarshalText() ([]byte, error) { return nil, invalidWork() }

// CaptchaUseReservationWork grants bounded SQL only during one native consuming
// reservation/rebind callback. It has no public constructor, driver, transaction
// closure or ordinary Work escape. Zero, foreign and returned handles deny.
// Copies share lifetime and cannot renew cancellation, SQL/result budgets,
// command generation, original expiry or owner lease. Serial use only.
type CaptchaUseReservationWork struct{ state *captchaUseReservationState }

type captchaUseReservationState struct {
	coordinator *Coordinator
	work        Work
	plan        *admittedKernelPlan
	command     identity.Command
	previous    uint64
	contributor CaptchaUseReservationContributor
	active      bool
}

// Format hides invocation authority.
func (CaptchaUseReservationWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CaptchaUseReservationWork(redacted)"))
}

// MarshalJSON denies invocation authority serialization.
func (CaptchaUseReservationWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText denies invocation authority serialization.
func (CaptchaUseReservationWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (w CaptchaUseReservationWork) usable() error {
	s := w.state
	if s == nil || !s.active || s.coordinator == nil || s.plan == nil || s.plan.captchaUse == nil || s.plan.feature == nil || s.work.state == nil || s.plan.belongsTo(s.coordinator.registry) != nil || s.work.state.registry != s.plan.registry || s.work.state.binding != s.plan.binding || s.plan.fingerprint == ([32]byte{}) || s.work.state.generation == 0 || s.previous != 0 && (s.previous == ^uint64(0) || s.work.state.generation != s.previous+1) {
		return invalidWork()
	}
	return s.work.usable()
}

// Binding checks active lifetime and exact registered instance before exposing
// owned scalar declarations. Nil/noncomparable/foreign owners fail without IO.
func (w CaptchaUseReservationWork) Binding(p CaptchaUseReservationContributor) (CaptchaUseReservationBinding, error) {
	if w.usable() != nil || nilContributor(p) || !reflect.TypeOf(p).Comparable() || p != w.state.contributor {
		return CaptchaUseReservationBinding{}, invalidWork()
	}
	s := w.state
	return CaptchaUseReservationBinding{Command: s.plan.binding, Plan: *s.plan.captchaUse, Fingerprint: s.plan.fingerprint, Generation: s.work.state.generation, PreviousGeneration: s.previous}, nil
}

// NativeCommand exposes complete immutable admitted input only to that owner.
// Its keyed fingerprint includes every original-flow and target-version field.
func (w CaptchaUseReservationWork) NativeCommand(p CaptchaUseReservationContributor) (identity.Command, error) {
	if _, err := w.Binding(p); err != nil {
		return identity.Command{}, err
	}
	return w.state.command, nil
}

// Exec runs one bounded trusted statement without transaction closure.
func (w CaptchaUseReservationWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query returns bounded callback-owned rows; close them before returning.
func (w CaptchaUseReservationWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime samples primary UTC without renewing original validity.
func (w CaptchaUseReservationWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func captchaUseReservationParticipant(c Contributor) (CaptchaUseReservationContributor, bool) {
	p, ok := c.(CaptchaUseReservationContributor)
	return p, ok && !nilContributor(p) && reflect.TypeOf(p).Comparable()
}

func captchaUseParticipant(p *admittedKernelPlan) CaptchaUseReservationContributor {
	if p == nil || p.captchaUse == nil {
		return nil
	}
	for _, entry := range p.contributors {
		if entry.descriptor == (ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}) {
			owner, _ := captchaUseReservationParticipant(entry.contributor)
			return owner
		}
	}
	return nil
}

func validateCaptchaUseCommand(p CaptchaUseReservationContributor, command identity.Command, plan CaptchaEvidencePlan) (err error) {
	defer func() {
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	if err := p.ValidateCaptchaUseCommand(command, plan); err != nil {
		_, _, _, safe := abortClassification(err)
		return safe
	}
	return nil
}

func (c *Coordinator) reserveCaptchaUse(ctx context.Context, tx pgx.Tx, command identity.Command, q claimRequest, p *admittedKernelPlan, j journalReservation, owner [16]byte) (err error) {
	if p.captchaUse == nil {
		return nil
	}
	participant := captchaUseParticipant(p)
	if participant == nil || p.feature == nil || p.belongsTo(c.registry) != nil || j.disposition != journalOwned || !bytes.Equal(q.safeFields, commandSafeFields(p.binding, &p.feature.Operation)) {
		return invalidPlan()
	}
	if err := validateCaptchaUseCommand(participant, command, *p.captchaUse); err != nil {
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
	s := &captchaUseReservationState{coordinator: c, work: work, plan: p, command: command, previous: j.previousGeneration, contributor: participant, active: true}
	defer func() {
		s.active = false
		s.command = identity.Command{}
		invalidateWork(work)
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	if err := configureKernelWork(ctx, work); err != nil {
		return err
	}
	handle := CaptchaUseReservationWork{state: s}
	if _, err := handle.Binding(participant); err != nil {
		return err
	}
	if j.previousGeneration == 0 {
		err = participant.ReserveCaptchaEvidence(ctx, handle)
	} else {
		err = participant.RebindCaptchaEvidence(ctx, handle)
	}
	if err != nil {
		return work.fail(ctx, err)
	}
	if work.state.rows != nil {
		return identity.UnavailableError{}
	}
	return work.usable()
}
