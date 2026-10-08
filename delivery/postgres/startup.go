package postgres

import (
	"context"
	"sync/atomic"

	"github.com/faustbrian/go-identity/delivery"
)

// startup is the only mutable service state. Owners and workers share this
// pointer; fields are frozen before publication. CAS bounds concurrent startup
// without holding a lock across database work or queueing unbounded waiters.
type enqueueStartup struct {
	initializing    atomic.Bool
	ready           atomic.Bool
	receiptTracking bool
}

// Initialize checks selected schema columns and registers the construction-time
// policy/namespace snapshot, without migrations, callbacks or business effects.
// One caller-derived Timeout bounds the entire attempt. Exact retries are safe;
// successful repeated calls do no IO. Concurrent attempts return ErrUnavailable
// rather than wait. Operations remain unavailable on every failure or uncertain
// acknowledgement. Registrations commit independently: policy rows can survive
// a namespace failure. Retained identity conflict is never silently repaired.
// Success enables existing and future Worker/Queue handles atomically. This is
// startup readiness, not ongoing dependency health or provider availability.
func (s *EnqueueService) Initialize(ctx context.Context) error {
	if ctx == nil || s == nil || s.startup == nil || s.executor == nil || s.keyed == nil || s.policies == nil {
		return delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	startup := s.startup
	if startup.ready.Load() {
		return nil
	}
	if !startup.initializing.CompareAndSwap(false, true) {
		return delivery.ErrUnavailable
	}
	defer startup.initializing.Store(false)
	// Another successful attempt may have published between our first read
	// and acquisition. Never reinterpret its immutable registration snapshot.
	if startup.ready.Load() {
		return nil
	}
	w, stop := context.WithTimeout(ctx, s.executor.timeout)
	defer stop()
	probes := make([]string, 0, 5)
	if s.stateTracking {
		probes = append(probes, `SELECT status_version,local_stop_state,local_stop_at FROM identity.delivery_intents WHERE false`)
	}
	if s.cancellation != nil {
		probes = append(probes, `SELECT binding_digest,generation,before_version,after_version,result_state,local_cancelled FROM identity.delivery_cancellations WHERE false`)
	}
	if s.receipts != nil {
		probes = append(probes, `SELECT r.event_digest,r.evidence_digest,r.observed_at,c.binding_digest,c.generation,c.before_version,c.after_version,c.result_state,c.advanced,c.deduplicated FROM identity.delivery_receipts r,identity.delivery_receipt_commands c WHERE false`)
	}
	if startup.receiptTracking {
		probes = append(probes, `SELECT result_state,observed_at,generation FROM identity.delivery_receipts WHERE false`)
	}
	if s.reconciliation != nil {
		probes = append(probes, `SELECT c.binding_digest,c.before_version,c.after_version,q.request_digest,q.query_digest,k.step,k.after_digest,v.ciphertext FROM identity.delivery_receipts r,identity.delivery_reconciliation_commands c,identity.delivery_reconciliation_queries q,identity.delivery_reconciliation_checkpoints k,identity.delivery_reconciliation_cursors v WHERE false`)
	}
	// Missing selected schemas deny before either independent registration.
	for _, query := range probes {
		if _, err := s.keyed.pool.Exec(w, query); err != nil {
			return attemptFailure(w, err)
		}
	}
	if err := s.policies.initialize(w); err != nil {
		return err
	}
	if err := s.keyed.initialize(w); err != nil {
		return err
	}
	if err := w.Err(); err != nil {
		return err
	}
	startup.ready.Store(true)
	return nil
}

func (s *EnqueueService) startupCheck(ctx context.Context) error {
	if ctx == nil || s == nil {
		return delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Low-level private fixtures/owners predate service composition; only the
	// public constructors create startup state. A public zero still has no
	// executor and is rejected by the operation's existing validation.
	if s.startup != nil && !s.startup.ready.Load() {
		return delivery.ErrUnavailable
	}
	return nil
}
