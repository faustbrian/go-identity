package postgres

import (
	"context"
	"fmt"
	"time"
)

// Only the coordinator selects provenance after its authoritative proof.
// Equal-generation rollback must never widen reservation/rebind authority.
type riskReleaseProof uint8

const (
	riskReleaseRecovery riskReleaseProof = iota + 1
	riskReleaseRollback
)

// RiskReleaseContributor supplies native noncommit evidence and terminal release.
// The coordinator invokes release only after all frozen participants prove
// recovery noncommit, or after it proves rollback and rechecks the live owner,
// under primary command and tenant exclusions. Release must CAS the
// exact reserved command/fingerprint/PreviousGeneration to terminal released,
// recording Generation. Recovery advances exactly one generation; proved
// live-owner rollback preserves generation. Expiry alone is never proof;
// expired reservations remain
// releasable after proof. No provider callbacks, private transactions, retained
// handles or reactivation are permitted. Independent invocations may run
// concurrently; their handles remain serial-use and invocation-bound.
type RiskReleaseContributor interface {
	RiskReservationContributor
	RecoveryContributor
	ReleaseRiskEvidence(context.Context, RiskReleaseWork) error
}

// RiskReleaseWork grants bounded terminal release, not reservation or domain
// authority. Zero and foreign handles are invalid. Copies expire on callback
// return or panic. Close rows before return; no transaction closure is exposed.
type RiskReleaseWork struct{ state *riskReservationState }

// Format redacts retained ownership and evidence metadata.
func (RiskReleaseWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.RiskReleaseWork(redacted)"))
}

// MarshalJSON rejects serialization of release authority.
func (RiskReleaseWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// MarshalText rejects serialization of release authority.
func (RiskReleaseWork) MarshalText() ([]byte, error) { return nil, invalidWork() }

// Binding checks exact registered identity and returns original frozen custody.
// PreviousGeneration is the reserved owner. Generation is the recovery
// successor, or the same live owner after the coordinator proves rollback.
func (w RiskReleaseWork) Binding(p RiskReleaseContributor) (RiskReservationBinding, error) {
	if err := w.usable(); err != nil {
		return RiskReservationBinding{}, err
	}
	return w.state.binding(p)
}

func (w RiskReleaseWork) usable() error {
	s := w.state
	if s == nil || s.previousGeneration == 0 || s.usable() != nil || !s.coordinator.owns(s.work) || s.work.state.execution.reservation.plan != s.plan {
		return invalidWork()
	}
	switch s.releaseProof {
	case riskReleaseRecovery:
		if s.previousGeneration == ^uint64(0) || s.work.state.generation != s.previousGeneration+1 {
			return invalidWork()
		}
	case riskReleaseRollback:
		if s.work.state.generation != s.previousGeneration {
			return invalidWork()
		}
	default:
		return invalidWork()
	}
	return nil
}

// Exec executes one bounded native release statement, never transaction closure.
func (w RiskReleaseWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query returns invocation-owned bounded rows; close them before return.
func (w RiskReleaseWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime reads primary UTC without renewing ownership or evidence expiry.
func (w RiskReleaseWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func (c *Coordinator) releaseRisk(ctx context.Context, work Work, p *admittedKernelPlan, j journalReservation) (err error) {
	return c.releaseRiskWithProof(ctx, work, p, j.previousGeneration, riskReleaseRecovery)
}

// Called only after Abort proves domain rollback and rechecks live ownership.
func (c *Coordinator) releaseRiskAfterRollback(ctx context.Context, work Work, p *admittedKernelPlan, j journalReservation) error {
	return c.releaseRiskWithProof(ctx, work, p, j.generation, riskReleaseRollback)
}

func (c *Coordinator) releaseRiskWithProof(ctx context.Context, work Work, p *admittedKernelPlan, previous uint64, proof riskReleaseProof) (err error) {
	if p.risk == nil {
		return nil
	}
	for _, entry := range p.contributors {
		if entry.descriptor.Owner != "identity/risk/postgres" {
			continue
		}
		participant, ok := entry.contributor.(RiskReleaseContributor)
		if !ok {
			return invalidWork()
		}
		state := &riskReservationState{coordinator: c, work: work, plan: p, previousGeneration: previous, active: true, contributor: participant, releaseProof: proof}
		defer func() {
			state.active = false
			if recover() != nil {
				err = work.fail(ctx, invalidWork())
			}
		}()
		handle := RiskReleaseWork{state: state}
		if _, err = handle.Binding(participant); err != nil {
			return err
		}
		if err = participant.ReleaseRiskEvidence(ctx, handle); err != nil {
			return work.fail(ctx, err)
		}
		if work.state.rows != nil {
			return work.fail(ctx, invalidWork())
		}
		return work.usable()
	}
	return invalidWork()
}
