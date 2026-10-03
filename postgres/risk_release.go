package postgres

import (
	"context"
	"fmt"
	"time"
)

// RiskReleaseContributor supplies native noncommit evidence and terminal release.
// The coordinator invokes release only after all frozen participants prove
// noncommit under primary command and tenant exclusions. Release must CAS the
// exact reserved command/fingerprint/PreviousGeneration to terminal released,
// recording Generation. Expiry alone is never proof; expired reservations remain
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
// Generation is the recovery owner; PreviousGeneration is the reserved owner.
func (w RiskReleaseWork) Binding(p RiskReleaseContributor) (RiskReservationBinding, error) {
	if w.state == nil || w.state.previousGeneration == 0 {
		return RiskReservationBinding{}, invalidWork()
	}
	return (RiskReservationWork{state: w.state}).Binding(p)
}

// Exec executes one bounded native release statement, never transaction closure.
func (w RiskReleaseWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	return (RiskReservationWork{state: w.state}).Exec(ctx, sql, args...)
}

// Query returns invocation-owned bounded rows; close them before return.
func (w RiskReleaseWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	return (RiskReservationWork{state: w.state}).Query(ctx, sql, args...)
}

// DatabaseTime reads primary UTC without renewing ownership or evidence expiry.
func (w RiskReleaseWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	return (RiskReservationWork{state: w.state}).DatabaseTime(ctx)
}

func (c *Coordinator) releaseRisk(ctx context.Context, work Work, p *admittedKernelPlan, j journalReservation) (err error) {
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
		state := &riskReservationState{coordinator: c, work: work, plan: p, previousGeneration: j.previousGeneration, active: true, contributor: participant}
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
