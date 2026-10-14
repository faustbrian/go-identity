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

// CaptchaReplayContributor is the native risk store's pre-domain issuance
// participant, invoked only by the sole coordinator. Reserve must authenticate
// the original signed command and current immutable configuration, atomically
// claim every retained token alias under one winner, and deny any different
// winner even after expiry. Rebind must conserve those aliases and CAS exactly
// PreviousGeneration to Generation. Domain rollback must not erase winners;
// elapsed time alone cannot release unresolved ownership. These methods issue
// no evidence, consume no protected use and disclose no bearer.
// Implementations verify Binding with their exact registered instance before
// SQL, close every row, return redacted errors and support concurrent calls
// with independent serial-use handles. No private transaction, network/provider
// callback, transaction closure or retained handle is permitted.
type CaptchaReplayContributor interface {
	FeatureExecutionContributor
	ReserveCaptchaReplay(context.Context, CaptchaReservationWork) error
	RebindCaptchaReplay(context.Context, CaptchaReservationWork) error
}

func captchaReplayParticipant(c Contributor) (CaptchaReplayContributor, bool) {
	p, ok := c.(CaptchaReplayContributor)
	return p, ok && !nilContributor(p) && reflect.TypeOf(p).Comparable()
}

func captchaReplayOperation(op identity.FeatureOperation) bool {
	schema := "identity-captcha-evidence-user-v1"
	if op.SubjectRequirement == identity.FeatureSubjectAnonymousFlow {
		schema = "identity-captcha-evidence-flow-v1"
	} else if op.SubjectRequirement != identity.FeatureSubjectUser {
		return false
	}
	return op == (identity.FeatureOperation{Owner: "identity/risk", OperationID: "identity.risk.captcha-issue", SchemaID: schema, SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: op.SubjectRequirement})
}

func validateCaptchaReplayPlan(b identity.CommandBinding, p CommandPlan) error {
	native := p.Feature != nil && captchaReplayOperation(p.Feature.Operation)
	if !p.CaptchaReplayReservation {
		if native {
			return invalidPlan()
		}
		return nil
	}
	if !native || p.SubjectType != "captcha_evidence" || b.RecordID != string(b.CommandID) || p.Feature.Contributor != (ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}) || p.RiskEvidence != nil || p.CommandCounters != nil || p.Capability != nil || p.CapabilityIssuance != nil || p.Delivery != nil {
		return invalidPlan()
	}
	return nil
}

// CaptchaReservationBinding owns the immutable original native command and
// authoritative retained-key fingerprint. Generation is positive;
// PreviousGeneration is zero for first reservation or the exact predecessor.
// This is invocation custody, not proof that provider verification, durable
// evidence, current authority or replay ownership exists. The participant must
// authenticate all original signed fields before changing its owned tables.
type CaptchaReservationBinding struct {
	Command                        identity.Command
	Fingerprint                    [32]byte
	Generation, PreviousGeneration uint64
}

func (CaptchaReservationBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CaptchaReservationBinding(redacted)"))
}
func (CaptchaReservationBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }
func (CaptchaReservationBinding) MarshalText() ([]byte, error) { return nil, invalidWork() }

// CaptchaReservationWork is coordinator-created SQL authority limited to one
// native callback. Zero/foreign/expired handles deny; copies share lifetime.
// Existing Work cancellation, SQL and row budgets apply. Time reads and copies
// cannot renew the owner lease. Serial use only; close rows before returning.
// No constructor, raw driver, transaction closure or ordinary Work escape exists.
type CaptchaReservationWork struct{ state *captchaReservationState }

type captchaReservationState struct {
	coordinator        *Coordinator
	work               Work
	plan               *admittedKernelPlan
	command            identity.Command
	previousGeneration uint64
	active             bool
	contributor        CaptchaReplayContributor
}

func (CaptchaReservationWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CaptchaReservationWork(redacted)"))
}
func (CaptchaReservationWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }
func (CaptchaReservationWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (w CaptchaReservationWork) usable() error {
	s := w.state
	if s == nil || !s.active || s.coordinator == nil || s.plan == nil || !s.plan.captchaReplay || s.plan.feature == nil || s.work.state == nil || s.plan.belongsTo(s.coordinator.registry) != nil || s.work.state.registry != s.plan.registry || s.work.state.binding != s.plan.binding || s.plan.fingerprint == ([32]byte{}) || s.work.state.generation == 0 || s.previousGeneration != 0 && (s.previousGeneration == ^uint64(0) || s.work.state.generation != s.previousGeneration+1) {
		return invalidWork()
	}
	return s.work.usable()
}

// Binding verifies callback lifetime and the exact registered participant
// identity before exposing original custody. Registration alone is not enough.
func (w CaptchaReservationWork) Binding(p CaptchaReplayContributor) (CaptchaReservationBinding, error) {
	if w.usable() != nil || nilContributor(p) || !reflect.TypeOf(p).Comparable() || p != w.state.contributor {
		return CaptchaReservationBinding{}, invalidWork()
	}
	s := w.state
	return CaptchaReservationBinding{Command: s.command, Fingerprint: s.plan.fingerprint, Generation: s.work.state.generation, PreviousGeneration: s.previousGeneration}, nil
}

// Exec runs one bounded trusted statement without transaction closure.
func (w CaptchaReservationWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query returns bounded callback-owned rows; close them before returning.
func (w CaptchaReservationWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime reads authoritative primary UTC without renewing validity.
func (w CaptchaReservationWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func (c *Coordinator) reserveCaptchaReplay(ctx context.Context, tx pgx.Tx, command identity.Command, q claimRequest, p *admittedKernelPlan, j journalReservation, owner [16]byte) (err error) {
	if !p.captchaReplay {
		return nil
	}
	spec, ok := command.Feature()
	if !ok || p.feature == nil || spec.Binding != p.binding || spec.Operation != p.feature.Operation || p.belongsTo(c.registry) != nil || j.disposition != journalOwned || !bytes.Equal(q.safeFields, commandSafeFields(p.binding, &p.feature.Operation)) {
		return invalidPlan()
	}
	entry, err := c.registry.selectFeatureOperation(*p.feature)
	if err != nil {
		return invalidPlan()
	}
	participant, ok := captchaReplayParticipant(entry.contributor)
	if !ok {
		return invalidPlan()
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
	s := &captchaReservationState{coordinator: c, work: work, plan: p, command: command, previousGeneration: j.previousGeneration, active: true, contributor: participant}
	defer func() {
		s.active = false
		invalidateWork(work)
		if recover() != nil {
			err = identity.UnavailableError{}
		}
	}()
	if err = configureKernelWork(ctx, work); err != nil {
		return err
	}
	w := CaptchaReservationWork{state: s}
	if err = w.usable(); err != nil {
		return err
	}
	if j.previousGeneration == 0 {
		err = participant.ReserveCaptchaReplay(ctx, w)
	} else {
		err = participant.RebindCaptchaReplay(ctx, w)
	}
	if err != nil {
		return work.fail(ctx, err)
	}
	if work.state.rows != nil {
		return identity.UnavailableError{}
	}
	return work.usable()
}
