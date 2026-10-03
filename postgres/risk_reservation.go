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

// RiskReservationContributor supplies risk's pre-domain phases. Only the sole
// Coordinator invokes them, inside the command reservation transaction. Reserve
// must authenticate the signed declaration, match current native scope/policy,
// and lock an already-issued exact row; it never inserts missing evidence or
// consumes a use. Rebind must CAS the same command/fingerprint from exactly
// PreviousGeneration to Generation. Missing, terminal, expired or mismatched
// rows fail closed, using primary database time and the original expiry.
// Implementations must verify their exact registered identity through Binding
// before SQL, close rows and return redacted errors. No provider/caller callbacks,
// retained Work, private transactions or transaction closure are permitted.
// Implementations must support concurrent invocations with serial-use handles.
// Registration/declaration alone supplies no authority to execute domain phases.
type RiskReservationContributor interface {
	Contributor
	ReserveRiskEvidence(context.Context, RiskReservationWork) error
	RebindRiskEvidence(context.Context, RiskReservationWork) error
}

func riskReservationParticipant(c Contributor) (RiskReservationContributor, bool) {
	p, ok := c.(RiskReservationContributor)
	return p, ok && !nilContributor(p) && reflect.TypeOf(p).Comparable()
}

// RiskReservationBinding is an owned scalar snapshot, never raw bearer or key
// material. Fingerprint is the authoritative retained-key consuming command
// fingerprint. Generation is positive; PreviousGeneration is zero for first
// reservation, otherwise the exact positive predecessor. Plan is declaration
// metadata, not proof of current authority, scope validation or row existence.
type RiskReservationBinding struct {
	Command                        identity.CommandBinding
	Plan                           RiskEvidencePlan
	Fingerprint                    [32]byte
	Generation, PreviousGeneration uint64
}

func (RiskReservationBinding) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RiskReservationBinding(redacted)"))
}
func (RiskReservationBinding) MarshalJSON() ([]byte, error) { return nil, invalidWork() }
func (RiskReservationBinding) MarshalText() ([]byte, error) { return nil, invalidWork() }

// RiskReservationWork is coordinator-created invocation-bound SQL authority.
// Zero and foreign instances are invalid. Copies share lifetime and expire on
// callback return or panic. Serial use only; close all rows before return.
// There is no raw driver, constructor, transaction closure or Work escape.
// Existing Work budgets apply; neither database time nor copies renew them.
type RiskReservationWork struct{ state *riskReservationState }

type riskReservationState struct {
	coordinator        *Coordinator
	work               Work
	plan               *admittedKernelPlan
	previousGeneration uint64
	active             bool
	contributor        RiskReservationContributor
}

func (RiskReservationWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RiskReservationWork(redacted)"))
}
func (RiskReservationWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }
func (RiskReservationWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

func (w RiskReservationWork) usable() error {
	s := w.state
	if s == nil || !s.active || s.coordinator == nil || s.plan == nil || s.plan.risk == nil || s.plan.feature == nil || s.work.state == nil || s.plan.belongsTo(s.coordinator.registry) != nil || s.work.state.registry != s.plan.registry || s.work.state.binding != s.plan.binding || s.plan.fingerprint == ([32]byte{}) || s.work.state.generation == 0 || s.previousGeneration != 0 && (s.previousGeneration == ^uint64(0) || s.work.state.generation != s.previousGeneration+1) {
		return invalidWork()
	}
	return s.work.usable()
}

// Binding verifies lifetime and exact registered participant identity before
// disclosing owned declarations. Pointer implementations use instance identity;
// comparable immutable values use value identity. Noncomparable/nil/foreign
// participants are denied before participant SQL.
func (w RiskReservationWork) Binding(p RiskReservationContributor) (RiskReservationBinding, error) {
	if err := w.usable(); err != nil {
		return RiskReservationBinding{}, err
	}
	if nilContributor(p) || !reflect.TypeOf(p).Comparable() || p != w.state.contributor {
		return RiskReservationBinding{}, invalidWork()
	}
	s := w.state
	return RiskReservationBinding{Command: s.plan.binding, Plan: *s.plan.risk, Fingerprint: s.plan.fingerprint, Generation: s.work.state.generation, PreviousGeneration: s.previousGeneration}, nil
}

// Exec runs one bounded trusted statement, never transaction closure.
func (w RiskReservationWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query returns bounded invocation-owned rows; close them before return.
func (w RiskReservationWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime reads authoritative primary UTC without renewing expiry.
func (w RiskReservationWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func (c *Coordinator) reserveRisk(ctx context.Context, tx pgx.Tx, q claimRequest, p *admittedKernelPlan, j journalReservation, owner [16]byte) (err error) {
	if p.risk == nil {
		return nil
	}
	if p.feature == nil || p.belongsTo(c.registry) != nil || j.disposition != journalOwned || !bytes.Equal(q.safeFields, commandSafeFields(p.binding, &p.feature.Operation)) {
		return invalidPlan()
	}
	var contributor RiskReservationContributor
	for _, entry := range p.contributors {
		if entry.descriptor == (ContributorDescriptor{Owner: "identity/risk/postgres", ContractID: "identity.risk.store", Version: 1}) {
			contributor, _ = riskReservationParticipant(entry.contributor)
		}
	}
	if contributor == nil {
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
	s := &riskReservationState{coordinator: c, work: work, plan: p, previousGeneration: j.previousGeneration, active: true, contributor: contributor}
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
	handle := RiskReservationWork{state: s}
	if err = handle.usable(); err != nil {
		return err
	}
	if j.previousGeneration == 0 {
		err = contributor.ReserveRiskEvidence(ctx, handle)
	} else {
		err = contributor.RebindRiskEvidence(ctx, handle)
	}
	if err != nil {
		return work.fail(ctx, err)
	}
	if work.state.rows != nil {
		return identity.UnavailableError{}
	}
	return work.usable()
}
