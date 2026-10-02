package postgres

import (
	"context"
	"fmt"
	"time"
)

// CapabilityReleaseContributor supplies authoritative status and terminal
// non-commit release for capability.one-use v1. Only Coordinator invokes these
// phases. Release must CAS the exact frozen reserved command, fingerprint and
// PreviousGeneration to terminal released (or expired after primary expiry),
// recording Generation. It must never issue, consume or reactivate a capability.
// The coordinator grants release authority only after every enlisted participant
// proves non-commit under the journal and tenant exclusions. Release, failure
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
	if w.state == nil || w.state.previousGeneration == 0 {
		return CapabilityReservationBinding{}, invalidWork()
	}
	return (CapabilityReservationWork{state: w.state}).Binding(p)
}

// Exec performs one bounded trusted participant statement, never closure.
func (w CapabilityReleaseWork) Exec(ctx context.Context, sql string, args ...any) (int64, error) {
	return (CapabilityReservationWork{state: w.state}).Exec(ctx, sql, args...)
}

// Query returns invocation-owned bounded rows; close them before returning.
func (w CapabilityReleaseWork) Query(ctx context.Context, sql string, args ...any) (*WorkRows, error) {
	return (CapabilityReservationWork{state: w.state}).Query(ctx, sql, args...)
}

// DatabaseTime reads primary UTC without extending the original lease.
func (w CapabilityReleaseWork) DatabaseTime(ctx context.Context) (time.Time, error) {
	return (CapabilityReservationWork{state: w.state}).DatabaseTime(ctx)
}

func (c *Coordinator) releaseCapability(ctx context.Context, work Work, p *admittedKernelPlan, j journalReservation) (err error) {
	if p.capability == nil {
		return nil
	}
	for _, entry := range p.contributors {
		if entry.descriptor.Owner != "capability/postgres" {
			continue
		}
		participant, ok := entry.contributor.(CapabilityReleaseContributor)
		if !ok {
			return invalidWork()
		}
		state := &capabilityReservationState{coordinator: c, work: work, plan: p, previousGeneration: j.previousGeneration, active: true, contributor: participant}
		defer func() {
			state.active = false
			if recover() != nil {
				err = invalidWork()
			}
		}()
		if _, err = (CapabilityReleaseWork{state: state}).Binding(participant); err != nil {
			return err
		}
		if err = participant.ReleaseCapability(ctx, CapabilityReleaseWork{state: state}); err != nil {
			return work.fail(ctx, err)
		}
		if work.state.rows != nil {
			return invalidWork()
		}
		return work.usable()
	}
	return invalidWork()
}
