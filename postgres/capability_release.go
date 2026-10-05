package postgres

import (
	"context"
	"fmt"
	"time"
)

// Provenance is private to the coordinator. Equal-generation rollback release
// must never widen reservation or takeover authority.
type capabilityReleaseProof uint8

const (
	capabilityReleaseRecovery capabilityReleaseProof = iota + 1
	capabilityReleaseRollback
)

// CapabilityReleaseContributor supplies authoritative status and terminal
// non-commit release for capability.one-use v1. Only Coordinator invokes these
// phases. Release must CAS the exact frozen reserved command, fingerprint and
// PreviousGeneration to terminal released (or expired after primary expiry),
// recording Generation. Recovery advances exactly one generation; proven
// live-owner rollback preserves it. It must never issue, consume or reactivate
// a capability. The coordinator grants release authority only after unanimous
// recovery noncommit evidence, or its own successful rollback and live-owner
// recheck, under journal and tenant exclusions. Release, failure
// audit and aborted receipt share one transaction; any failure rolls them back.
// Reservation callback restrictions, concurrency and resource limits also apply.
type CapabilityReleaseContributor interface {
	CapabilityReservationContributor
	RecoveryContributor
	ReleaseCapability(context.Context, CapabilityReleaseWork) error
}

// CapabilityReleaseWork is an invocation-bound terminal-release capability.
// There is no constructor or transaction closure. Copies expire on callback
// return, including panic. Serial use only; close all rows before returning.
// It is never granted on lease/expiry alone or unresolved participant evidence.
type CapabilityReleaseWork struct{ state *capabilityReservationState }

// Format redacts transaction and retained binding metadata.
func (CapabilityReleaseWork) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.CapabilityReleaseWork(redacted)"))
}

// MarshalJSON rejects serialization of terminal-release authority.
func (CapabilityReleaseWork) MarshalJSON() ([]byte, error) { return nil, invalidWork() }

// Binding returns the exact frozen input and ownership generations, after
// checking the registered contributor's identity and invocation lifetime.
func (w CapabilityReleaseWork) Binding(p CapabilityReleaseContributor) (CapabilityReservationBinding, error) {
	if err := w.usable(); err != nil {
		return CapabilityReservationBinding{}, err
	}
	return w.state.binding(p)
}

func (w CapabilityReleaseWork) usable() error {
	s := w.state
	if s == nil || s.previousGeneration == 0 || s.usable() != nil || !s.coordinator.owns(s.work) || s.work.state.execution.reservation.plan != s.plan {
		return invalidWork()
	}
	switch s.releaseProof {
	case capabilityReleaseRecovery:
		if s.previousGeneration == ^uint64(0) || s.work.state.generation != s.previousGeneration+1 {
			return invalidWork()
		}
	case capabilityReleaseRollback:
		if s.work.state.generation != s.previousGeneration {
			return invalidWork()
		}
	default:
		return invalidWork()
	}
	return nil
}

// Exec performs one bounded trusted participant statement, never closure.
func (w CapabilityReleaseWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	if err := w.usable(); err != nil {
		return 0, err
	}
	return w.state.work.Exec(ctx, sql, args...)
}

// Query returns invocation-owned bounded rows; close them before returning.
func (w CapabilityReleaseWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	if err := w.usable(); err != nil {
		return nil, err
	}
	return w.state.work.Query(ctx, sql, args...)
}

// DatabaseTime reads primary UTC without extending the original lease.
func (w CapabilityReleaseWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	return w.state.work.DatabaseTime(ctx)
}

func (c *Coordinator) releaseCapability(ctx context.Context, work Work, p *admittedKernelPlan, j journalReservation) (err error) {
	return c.releaseCapabilityWithProof(ctx, work, p, j.previousGeneration, capabilityReleaseRecovery)
}

// Called only after Abort proves rollback and rechecks the original live owner.
func (c *Coordinator) releaseCapabilityAfterRollback(ctx context.Context, work Work, p *admittedKernelPlan, j journalReservation) error {
	return c.releaseCapabilityWithProof(ctx, work, p, j.generation, capabilityReleaseRollback)
}

func (c *Coordinator) releaseCapabilityWithProof(ctx context.Context, work Work, p *admittedKernelPlan, previous uint64, proof capabilityReleaseProof) (err error) {
	if p.capability == nil {
		return nil
	}
	for _, entry := range p.contributors {
		if entry.descriptor.Owner != "capability/postgres" || entry.descriptor.ContractID != "capability.one-use" {
			continue
		}
		participant, ok := entry.contributor.(CapabilityReleaseContributor)
		if !ok {
			return invalidWork()
		}
		state := &capabilityReservationState{coordinator: c, work: work, plan: p, previousGeneration: previous, active: true, contributor: participant, releaseProof: proof}
		defer func() {
			state.active = false
			if recover() != nil {
				err = work.fail(ctx, invalidWork())
			}
		}()
		if _, err = (CapabilityReleaseWork{state: state}).Binding(participant); err != nil {
			return err
		}
		if err = participant.ReleaseCapability(ctx, CapabilityReleaseWork{state: state}); err != nil {
			return work.fail(ctx, err)
		}
		if work.state.rows != nil {
			return work.fail(ctx, invalidWork())
		}
		return work.usable()
	}
	return invalidWork()
}
