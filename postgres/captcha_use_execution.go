package postgres

import (
	"context"
	"fmt"
	"reflect"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// CaptchaExecutionContributor opts the exact consuming owner into domain use.
// Check authenticates original/consumer custody, current flow/policy/profile and
// exclusive primary expiry under exclusion, before mutation and before finalize.
// Finalize rechecks then CASes exactly reserved command/fingerprint/generation
// to terminal finalized in the same transaction as domain/effects/result.
// Release runs only after coordinator-proven rollback or unanimous primary
// noncommit evidence; expiry/lease loss alone is never proof. All methods close
// rows, retain no handles, run no providers/private transactions or retries, and
// support independent concurrent invocations with serial-use handles. Domain
// owners separately check current user/session/factor and target authority.
type CaptchaExecutionContributor interface {
	CaptchaUseReservationContributor
	CheckCaptchaEvidence(context.Context, CaptchaApplyWork) error
	FinalizeCaptchaEvidence(context.Context, CaptchaFinalizeWork) error
	ReleaseCaptchaEvidence(context.Context, CaptchaReleaseWork) error
}

type captchaExecutionPhase uint8

const (
	captchaCheck captchaExecutionPhase = iota + 1
	captchaFinalize
	captchaRelease
)

type captchaExecutionState struct {
	reservation captchaUseReservationState
	phase       captchaExecutionPhase
	proof       riskReleaseProof
}

func (s *captchaExecutionState) usable(phase captchaExecutionPhase) error {
	if s == nil || s.phase != phase || !s.reservation.active || s.reservation.coordinator == nil ||
		s.reservation.plan == nil || s.reservation.plan.captchaUse == nil || s.reservation.plan.feature == nil ||
		s.reservation.plan.fingerprint == ([32]byte{}) || !s.reservation.coordinator.owns(s.reservation.work) ||
		s.reservation.plan.belongsTo(s.reservation.coordinator.registry) != nil ||
		s.reservation.work.state.binding != s.reservation.plan.binding ||
		s.reservation.work.state.execution.reservation.plan != s.reservation.plan || s.reservation.work.state.generation == 0 {
		return invalidWork()
	}
	r := &s.reservation
	if phase != captchaRelease {
		if r.previous != 0 || s.proof != 0 {
			return invalidWork()
		}
	} else {
		if r.previous == 0 {
			return invalidWork()
		}
		switch s.proof {
		case riskReleaseRollback:
			if r.work.state.generation != r.previous {
				return invalidWork()
			}
		case riskReleaseRecovery:
			if r.previous == ^uint64(0) || r.work.state.generation != r.previous+1 {
				return invalidWork()
			}
		default:
			return invalidWork()
		}
	}
	return r.work.usable()
}

func (s *captchaExecutionState) binding(p CaptchaUseReservationContributor, phase captchaExecutionPhase) (CaptchaUseReservationBinding, error) {
	if s.usable(phase) != nil || nilContributor(p) || !reflect.TypeOf(p).Comparable() || p != s.reservation.contributor {
		return CaptchaUseReservationBinding{}, invalidWork()
	}
	r := &s.reservation
	return CaptchaUseReservationBinding{Command: r.plan.binding, Plan: *r.plan.captchaUse, Fingerprint: r.plan.fingerprint, Generation: r.work.state.generation, PreviousGeneration: r.previous}, nil
}

func (s *captchaExecutionState) nativeCommand(p CaptchaUseReservationContributor, phase captchaExecutionPhase) (identity.Command, error) {
	if _, err := s.binding(p, phase); err != nil {
		return identity.Command{}, err
	}
	return s.reservation.command, nil
}

// CaptchaApplyWork grants exact invocation-owned primary reads, not mutations,
// provider access or transaction closure. Trusted read/locking SQL only. Zero,
// foreign and returned handles deny; copies share cancellation and lifetime.
// Use serially and close rows before callback return.
type CaptchaApplyWork struct{ state *captchaExecutionState }

// Format redacts native custody and invocation authority.
func (CaptchaApplyWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CaptchaApplyWork(redacted)"))
}

// MarshalJSON denies invocation serialization.
func (CaptchaApplyWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText denies invocation serialization.
func (CaptchaApplyWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding returns current exact-owner custody; it grants no release authority.
func (w CaptchaApplyWork) Binding(p CaptchaUseReservationContributor) (CaptchaUseReservationBinding, error) {
	return w.state.binding(p, captchaCheck)
}

// NativeCommand returns immutable authenticated input to the exact owner.
func (w CaptchaApplyWork) NativeCommand(p CaptchaUseReservationContributor) (identity.Command, error) {
	return w.state.nativeCommand(p, captchaCheck)
}

// Query reads bounded primary rows without escaping Work ownership.
func (w CaptchaApplyWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.state.usable(captchaCheck); err != nil {
		return nil, err
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// DatabaseTime samples primary UTC without renewing original validity.
func (w CaptchaApplyWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.state.usable(captchaCheck); err != nil {
		return time.Time{}, err
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

// CaptchaFinalizeWork grants invocation-owned terminal CAS in the domain
// transaction after provisional protected effects. It permits no release,
// renewal, private commit or retained rows. Copies share lifetime; serial use.
type CaptchaFinalizeWork struct{ state *captchaExecutionState }

// Format redacts terminal authority.
func (CaptchaFinalizeWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CaptchaFinalizeWork(redacted)"))
}

// MarshalJSON denies terminal authority serialization.
func (CaptchaFinalizeWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText denies terminal authority serialization.
func (CaptchaFinalizeWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding returns exact current-generation custody, not noncommit proof.
func (w CaptchaFinalizeWork) Binding(p CaptchaUseReservationContributor) (CaptchaUseReservationBinding, error) {
	return w.state.binding(p, captchaFinalize)
}

// NativeCommand returns the same admitted input to the exact native owner.
func (w CaptchaFinalizeWork) NativeCommand(p CaptchaUseReservationContributor) (identity.Command, error) {
	return w.state.nativeCommand(p, captchaFinalize)
}

// Query returns bounded callback-owned rows; close them before returning.
func (w CaptchaFinalizeWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.state.usable(captchaFinalize); err != nil {
		return nil, err
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// Exec performs trusted terminal SQL, never transaction closure.
func (w CaptchaFinalizeWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.state.usable(captchaFinalize); err != nil {
		return 0, err
	}
	return w.state.reservation.work.Exec(ctx, sql, args...)
}

// DatabaseTime cannot renew evidence, command lease or invocation lifetime.
func (w CaptchaFinalizeWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.state.usable(captchaFinalize); err != nil {
		return time.Time{}, err
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

// CaptchaReleaseWork grants terminal release only after primary noncommit proof.
// Binding carries the exact reserved predecessor and recovery successor, or the
// unchanged live owner after proven rollback. Expired evidence is releasable
// after proof, never reusable. Zero/foreign/retained handles deny, copies share
// lifetime; serial use and bounded SQL only, with no private closure.
type CaptchaReleaseWork struct{ state *captchaExecutionState }

// Format redacts proof-bound authority.
func (CaptchaReleaseWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CaptchaReleaseWork(redacted)"))
}

// MarshalJSON denies release authority serialization.
func (CaptchaReleaseWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText denies release authority serialization.
func (CaptchaReleaseWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding checks exact registered ownership and frozen original linkage.
func (w CaptchaReleaseWork) Binding(p CaptchaUseReservationContributor) (CaptchaUseReservationBinding, error) {
	return w.state.binding(p, captchaRelease)
}

// Query reads bounded primary rows; close each before callback return.
func (w CaptchaReleaseWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.state.usable(captchaRelease); err != nil {
		return nil, err
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// Exec performs bounded terminal release SQL without private commit.
func (w CaptchaReleaseWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.state.usable(captchaRelease); err != nil {
		return 0, err
	}
	return w.state.reservation.work.Exec(ctx, sql, args...)
}

// DatabaseTime samples primary UTC; expiry alone is not release proof.
func (w CaptchaReleaseWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.state.usable(captchaRelease); err != nil {
		return time.Time{}, err
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

func captchaExecutionParticipant(p *admittedKernelPlan) CaptchaExecutionContributor {
	owner, ok := captchaUseParticipant(p).(CaptchaExecutionContributor)
	if !ok {
		return nil
	}
	return owner
}

func (c *Coordinator) runCaptchaExecution(ctx context.Context, w Work, command identity.Command, phase captchaExecutionPhase) (err error) {
	p := w.state.execution.reservation.plan
	if p.captchaUse == nil {
		return nil
	}
	owner := captchaExecutionParticipant(p)
	if owner == nil || (phase != captchaCheck && phase != captchaFinalize) {
		return w.fail(ctx, invalidWork())
	}
	if err := validateCaptchaUseCommand(owner, command, *p.captchaUse); err != nil {
		return w.fail(ctx, err)
	}
	s := &captchaExecutionState{reservation: captchaUseReservationState{coordinator: c, work: w, plan: p, command: command, contributor: owner, active: true}, phase: phase}
	defer func() {
		s.reservation.active = false
		s.reservation.command = identity.Command{}
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if err = s.usable(phase); err != nil {
		return w.fail(ctx, err)
	}
	if phase == captchaCheck {
		err = owner.CheckCaptchaEvidence(ctx, CaptchaApplyWork{state: s})
	} else {
		err = owner.FinalizeCaptchaEvidence(ctx, CaptchaFinalizeWork{state: s})
	}
	if err != nil {
		_, _, _, safe := abortClassification(err)
		return w.fail(ctx, safe)
	}
	if w.state.rows != nil || w.usable() != nil {
		return w.fail(ctx, identity.UnavailableError{})
	}
	return nil
}

func (c *Coordinator) releaseCaptcha(ctx context.Context, w Work, p *admittedKernelPlan, previous uint64, proof riskReleaseProof) (err error) {
	if p.captchaUse == nil {
		return nil
	}
	owner := captchaExecutionParticipant(p)
	if owner == nil {
		return invalidWork()
	}
	s := &captchaExecutionState{reservation: captchaUseReservationState{coordinator: c, work: w, plan: p, contributor: owner, previous: previous, active: true}, phase: captchaRelease, proof: proof}
	defer func() {
		s.reservation.active = false
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if _, err = (CaptchaReleaseWork{state: s}).Binding(owner); err != nil {
		return err
	}
	if err = owner.ReleaseCaptchaEvidence(ctx, CaptchaReleaseWork{state: s}); err != nil {
		return w.fail(ctx, err)
	}
	if w.state.rows != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.usable()
}
