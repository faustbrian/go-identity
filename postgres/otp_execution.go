package postgres

import (
	"context"
	"fmt"
	"reflect"
	"time"

	authentication "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
)

// OTPExecutionContributor opts the exact reservation owner into protected use.
// CheckOTP checks current purpose, subject, workflow, authorization, target
// versions, reserved generation and exclusive primary expiry under exclusion.
// It never compares or meters the submitted code again. FinalizeOTP rechecks
// those invariants and CASes reserved to finalized in the same transaction as
// protected effects and the result. ReleaseOTP terminally releases only after
// coordinator-proven rollback or unanimous primary noncommit evidence; expiry
// or lease loss alone is not proof. Methods retain no handles, close every row,
// open no private transaction, make no network calls and perform no retries.
// Instances support concurrent callbacks; each supplied handle is serial-use.
type OTPExecutionContributor interface {
	OTPReservationContributor
	CheckOTP(context.Context, OTPApplyWork) error
	FinalizeOTP(context.Context, OTPFinalizeWork) error
	ReleaseOTP(context.Context, OTPReleaseWork) error
}

type otpExecutionPhase uint8

const (
	otpCheck otpExecutionPhase = iota + 1
	otpFinalize
	otpRelease
)

type otpExecutionState struct {
	reservation otpReservationState
	phase       otpExecutionPhase
	proof       riskReleaseProof
}

func (s *otpExecutionState) usable(phase otpExecutionPhase) error {
	if s == nil || s.phase != phase || !s.reservation.active || s.reservation.coordinator == nil ||
		s.reservation.plan == nil || s.reservation.plan.otp == nil || s.reservation.plan.otp.Mode != OTPConsume ||
		s.reservation.plan.feature == nil || s.reservation.plan.fingerprint == ([32]byte{}) ||
		!s.reservation.coordinator.owns(s.reservation.work) ||
		s.reservation.plan.belongsTo(s.reservation.coordinator.registry) != nil ||
		s.reservation.work.state.binding != s.reservation.plan.binding ||
		s.reservation.work.state.execution.reservation.plan != s.reservation.plan || s.reservation.work.state.generation == 0 {
		return invalidWork()
	}
	r := &s.reservation
	if phase != otpRelease {
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

func (s *otpExecutionState) binding(owner OTPReservationContributor, phase otpExecutionPhase) (OTPReservationBinding, error) {
	if s.usable(phase) != nil || nilContributor(owner) || !reflect.TypeOf(owner).Comparable() || owner != s.reservation.owner {
		return OTPReservationBinding{}, invalidWork()
	}
	r := &s.reservation
	return OTPReservationBinding{Command: r.plan.binding, Plan: *r.plan.otp, Fingerprint: r.plan.fingerprint, Generation: r.work.state.generation, PreviousGeneration: r.previous}, nil
}

func (s *otpExecutionState) commandSpec(owner OTPReservationContributor, phase otpExecutionPhase) (identity.FeatureCommandSpec, error) {
	if _, err := s.binding(owner, phase); err != nil {
		return identity.FeatureCommandSpec{}, err
	}
	spec, ok := s.reservation.command.Feature()
	if !ok && phoneResetConsumptionPlan(s.reservation.plan.snapshot()) {
		spec, ok = s.reservation.command.PhonePasswordResetFeature()
	}
	if !ok || spec.Binding != s.reservation.plan.binding || spec.Operation != s.reservation.plan.feature.Operation {
		return identity.FeatureCommandSpec{}, invalidWork()
	}
	return spec, nil
}

func (s *otpExecutionState) preAuthCookie(owner OTPReservationContributor, phase otpExecutionPhase) (authentication.BearerCredential, error) {
	if _, err := s.binding(owner, phase); err != nil {
		return authentication.BearerCredential{}, err
	}
	cookie, ok := s.reservation.command.PreAuthCookie()
	if !ok && phoneResetConsumptionPlan(s.reservation.plan.snapshot()) {
		cookie, ok = s.reservation.command.PhonePasswordResetPreAuthCookie()
	}
	if !ok {
		return authentication.BearerCredential{}, invalidWork()
	}
	return cookie, nil
}

func (s *otpExecutionState) sessionToken(owner OTPReservationContributor, phase otpExecutionPhase) (authentication.BearerCredential, error) {
	if _, err := s.binding(owner, phase); err != nil {
		return authentication.BearerCredential{}, err
	}
	token, ok := s.reservation.command.SessionToken()
	if !ok {
		return authentication.BearerCredential{}, invalidWork()
	}
	return token, nil
}

// OTPApplyWork grants exact-owner primary reads during current checks, not
// mutation, submitted-code access or transaction closure. Zero/foreign/returned
// handles deny; copies share callback lifetime. Use serially and close rows.
type OTPApplyWork struct{ state *otpExecutionState }

// Format redacts invocation authority.
func (OTPApplyWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPApplyWork(redacted)"))
}

// MarshalJSON denies authority serialization.
func (OTPApplyWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText denies authority serialization.
func (OTPApplyWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding returns live exact-owner frozen custody, not release proof.
func (w OTPApplyWork) Binding(p OTPReservationContributor) (OTPReservationBinding, error) {
	return w.state.binding(p, otpCheck)
}

// RequireFeatureOrigin correlates an opaque native completion receipt with its
// originating protected Work during the final phone-reset OTP check. Both
// contributor instances must be the exact registered owners, and origin must
// share the live private Work state, original plan and generation. Identical
// scalar metadata from another Work is insufficient. Only a completed phone
// Apply is accepted; this grants no SQL, factor verdict or mutation authority.
// A trusted receipt owner may retain origin privately until this transaction
// closes, solely for this guard; callers must not retain or reuse general Work
// access. Zero, foreign, returned, canceled and other-profile handles deny.
// No IO, contributor callback, code comparison or freshness renewal occurs.
func (w OTPApplyWork) RequireFeatureOrigin(ctx context.Context, otpOwner OTPReservationContributor, featureOwner FeatureExecutionContributor, origin Work) error {
	if ctx == nil {
		return invalidWork()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := w.Binding(otpOwner)
	if err != nil {
		return err
	}
	s := &w.state.reservation
	p := s.plan
	if origin.state != s.work.state || !phoneResetConsumptionPlan(p.snapshot()) ||
		origin.state.featureApplying || origin.state.featureInvocation != nil ||
		!origin.state.featureAttempted || origin.state.featureReceipt == nil ||
		origin.state.featureReceipt.Operation != p.feature.Operation ||
		origin.state.feature == nil || *origin.state.feature != *p.feature ||
		origin.state.execution.reservation.journal.generation != b.Generation {
		return invalidWork()
	}
	entry, err := s.coordinator.registry.selectFeatureOperation(*p.feature)
	if err != nil || !sameParticipant(entry.contributor, featureOwner) {
		return invalidWork()
	}
	return nil
}

// CommandSpec returns code-free original feature scope to the exact owner.
func (w OTPApplyWork) CommandSpec(p OTPReservationContributor) (identity.FeatureCommandSpec, error) {
	return w.state.commandSpec(p, otpCheck)
}

// PreAuthCookie lends only the actual submitted pre-auth bearer to the exact
// live owner, independently of the code-free CommandSpec. It grants neither
// cookie possession proof nor authentication; the owner must derive and check
// the original flow commitment against primary session state. Missing, foreign,
// zero and returned handles return zero and InvalidInput. Do not retain, log,
// persist or serialize the borrowed bearer. No OTP code is exposed.
func (w OTPApplyWork) PreAuthCookie(p OTPReservationContributor) (authentication.BearerCredential, error) {
	return w.state.preAuthCookie(p, otpCheck)
}

// SessionToken lends only the separately submitted session bearer to the exact
// live owner. Missing, pre-auth, foreign, zero and returned handles deny. This
// grants no authentication or validity; the owner must derive the original
// lookup digest and check every applicable primary authority. Never retain, log,
// persist or serialize the borrowed token. Neither code nor native Command is
// exposed; release/recovery phases deliberately have no bearer accessor.
func (w OTPApplyWork) SessionToken(p OTPReservationContributor) (authentication.BearerCredential, error) {
	return w.state.sessionToken(p, otpCheck)
}

// Query grants bounded trusted primary reads; close rows before returning.
func (w OTPApplyWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.state.usable(otpCheck); err != nil {
		return nil, err
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// DatabaseTime samples primary UTC without renewing challenge validity.
func (w OTPApplyWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.state.usable(otpCheck); err != nil {
		return time.Time{}, err
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

// OTPFinalizeWork grants terminal CAS in the protected transaction, never
// code comparison, private commit or release. Copies share callback lifetime;
// use serially and close rows. Zero/foreign/returned handles deny.
type OTPFinalizeWork struct{ state *otpExecutionState }

// Format redacts terminal authority.
func (OTPFinalizeWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPFinalizeWork(redacted)"))
}

// MarshalJSON denies authority serialization.
func (OTPFinalizeWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText denies authority serialization.
func (OTPFinalizeWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding returns exact current-generation custody, not noncommit proof.
func (w OTPFinalizeWork) Binding(p OTPReservationContributor) (OTPReservationBinding, error) {
	return w.state.binding(p, otpFinalize)
}

// CommandSpec returns code-free immutable scope, never the submitted code.
func (w OTPFinalizeWork) CommandSpec(p OTPReservationContributor) (identity.FeatureCommandSpec, error) {
	return w.state.commandSpec(p, otpFinalize)
}

// PreAuthCookie lends the separately submitted original bearer only during
// exact-owner finalization. Semantics and secret-handling requirements match
// OTPApplyWork.PreAuthCookie; release and recovery never receive this access.
func (w OTPFinalizeWork) PreAuthCookie(p OTPReservationContributor) (authentication.BearerCredential, error) {
	return w.state.preAuthCookie(p, otpFinalize)
}

// SessionToken lends the original session bearer to its registered reservation
// owner during finalization. Its custody and authority rules are identical to
// OTPApplyWork.SessionToken. It does not provide the submitted code.
func (w OTPFinalizeWork) SessionToken(p OTPReservationContributor) (authentication.BearerCredential, error) {
	return w.state.sessionToken(p, otpFinalize)
}

// Query reads bounded callback-owned rows; close them before returning.
func (w OTPFinalizeWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.state.usable(otpFinalize); err != nil {
		return nil, err
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// Exec performs bounded trusted terminal SQL without transaction closure.
func (w OTPFinalizeWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.state.usable(otpFinalize); err != nil {
		return 0, err
	}
	return w.state.reservation.work.Exec(ctx, sql, args...)
}

// DatabaseTime cannot renew original expiry or invocation lifetime.
func (w OTPFinalizeWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.state.usable(otpFinalize); err != nil {
		return time.Time{}, err
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

// OTPReleaseWork grants terminal release only after authoritative noncommit
// proof. Binding carries the exact reserved predecessor; recovery uses its
// successor, rollback its unchanged owner. Expiry alone grants no proof.
// Copies share lifetime; zero/foreign/returned handles deny. Use serially.
type OTPReleaseWork struct{ state *otpExecutionState }

// Format redacts proof-bound authority.
func (OTPReleaseWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.OTPReleaseWork(redacted)"))
}

// MarshalJSON denies authority serialization.
func (OTPReleaseWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText denies authority serialization.
func (OTPReleaseWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding checks exact registered ownership and frozen linkage.
func (w OTPReleaseWork) Binding(p OTPReservationContributor) (OTPReservationBinding, error) {
	return w.state.binding(p, otpRelease)
}

// Query reads bounded primary rows; close them before callback return.
func (w OTPReleaseWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.state.usable(otpRelease); err != nil {
		return nil, err
	}
	return w.state.reservation.work.Query(ctx, sql, args...)
}

// Exec performs terminal release SQL, never private transaction closure.
func (w OTPReleaseWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.state.usable(otpRelease); err != nil {
		return 0, err
	}
	return w.state.reservation.work.Exec(ctx, sql, args...)
}

// DatabaseTime samples primary UTC; expiry alone is not release proof.
func (w OTPReleaseWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.state.usable(otpRelease); err != nil {
		return time.Time{}, err
	}
	return w.state.reservation.work.DatabaseTime(ctx)
}

func otpExecutionOwner(p *admittedKernelPlan) OTPExecutionContributor {
	owner, _ := otpReservationOwner(p).(OTPExecutionContributor)
	return owner
}

func (c *Coordinator) runOTPExecution(ctx context.Context, w Work, command identity.Command, phase otpExecutionPhase) (err error) {
	p := w.state.execution.reservation.plan
	if p.otp == nil {
		return nil
	}
	owner := otpExecutionOwner(p)
	if owner == nil || (phase != otpCheck && phase != otpFinalize) {
		return w.fail(ctx, invalidWork())
	}
	if err := validateOTPAttempt(owner, command, *p.otp); err != nil {
		return w.fail(ctx, err)
	}
	s := &otpExecutionState{reservation: otpReservationState{coordinator: c, work: w, plan: p, command: command, owner: owner, active: true}, phase: phase}
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
	if phase == otpCheck {
		err = owner.CheckOTP(ctx, OTPApplyWork{state: s})
	} else {
		err = owner.FinalizeOTP(ctx, OTPFinalizeWork{state: s})
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

func (c *Coordinator) releaseOTP(ctx context.Context, w Work, p *admittedKernelPlan, previous uint64, proof riskReleaseProof) (err error) {
	if p.otp == nil {
		return nil
	}
	owner := otpExecutionOwner(p)
	if owner == nil {
		return invalidWork()
	}
	s := &otpExecutionState{reservation: otpReservationState{coordinator: c, work: w, plan: p, owner: owner, previous: previous, active: true}, phase: otpRelease, proof: proof}
	defer func() {
		s.reservation.active = false
		if recover() != nil {
			err = w.fail(ctx, identity.UnavailableError{})
		}
	}()
	if _, err = (OTPReleaseWork{state: s}).Binding(owner); err != nil {
		return err
	}
	if err = owner.ReleaseOTP(ctx, OTPReleaseWork{state: s}); err != nil {
		_, _, _, safe := abortClassification(err)
		return w.fail(ctx, safe)
	}
	if w.state.rows != nil {
		return w.fail(ctx, invalidWork())
	}
	return w.usable()
}
