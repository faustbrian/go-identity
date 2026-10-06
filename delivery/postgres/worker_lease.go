package postgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-identity/delivery"
)

// RenewLease heartbeats an existing committed claim in this worker's configured
// tenant, worker and retained provider profile. Intent and generation must be
// kept unchanged from Claim. Current service-account policy is checked before
// database ownership. The acknowledged database deadline never exceeds original
// attempt start plus one minute or original message expiry; no authority, attempt,
// status version or provider observation is renewed. No goroutine is started.
// A zero deadline accompanies every failure, including an unknown commit. Never
// invoke a provider beyond the last acknowledged lease deadline.
func (w *Worker) RenewLease(ctx context.Context, intent delivery.IntentID, generation uint32) (time.Time, error) {
	if w == nil || w.queue == nil {
		return time.Time{}, delivery.ErrInvalidInput
	}
	return w.queue.renewLease(ctx, intent, generation)
}

// ReleaseLease relinquishes this exact possibly invoked claim as outcome-unknown,
// never transient failure or permission to resend. Current policy and retained
// tenant/worker/provider fences apply to observation and replay. Completion audit,
// unknown state and lease removal commit together; uncertain acknowledgement
// returns no successful result. Exact retries recover the original outcome without
// another event or invocation. Use Complete(Invoked=false) only when no invocation
// is positively known. Neither method can undo a provider call already in flight.
func (w *Worker) ReleaseLease(ctx context.Context, intent delivery.IntentID, generation uint32) (delivery.CompleteResult, error) {
	if w == nil || w.queue == nil {
		return delivery.CompleteResult{}, delivery.ErrInvalidInput
	}
	return w.queue.releaseLease(ctx, intent, generation)
}

// RenewLease exposes the same configured heartbeat owner as Worker.RenewLease.
// It does not enlarge delivery.Queue or change Service.ProcessOne scheduling.
func (q *Queue) RenewLease(ctx context.Context, intent delivery.IntentID, generation uint32) (time.Time, error) {
	if q == nil || q.worker == nil {
		return time.Time{}, delivery.ErrInvalidInput
	}
	return q.worker.renewLease(ctx, intent, generation)
}

// ReleaseLease exposes the same conservative outcome owner as Worker.ReleaseLease.
// No provider cancellation, query, send or automatic retry is performed.
func (q *Queue) ReleaseLease(ctx context.Context, intent delivery.IntentID, generation uint32) (delivery.CompleteResult, error) {
	if q == nil || q.worker == nil {
		return delivery.CompleteResult{}, delivery.ErrInvalidInput
	}
	return q.worker.releaseLease(ctx, intent, generation)
}

func (q *workerQueue) leaseContext(ctx context.Context, intent delivery.IntentID, generation uint32) (context.Context, context.CancelFunc, leaseFence, error) {
	if q == nil || q.store == nil {
		return nil, nil, leaseFence{}, delivery.ErrInvalidInput
	}
	f := leaseFence{TenantID: q.request.TenantID, WorkerID: q.request.WorkerID, IntentID: intent, Generation: generation}
	if f.completion().Validate() != nil {
		return nil, nil, leaseFence{}, delivery.ErrInvalidInput
	}
	w, stop, err := q.store.bounded(ctx)
	if err != nil {
		return nil, nil, leaseFence{}, err
	}
	if err := q.allow(w); err != nil {
		stop()
		return nil, nil, leaseFence{}, err
	}
	return w, stop, f, nil
}

func (q *workerQueue) renewLease(ctx context.Context, intent delivery.IntentID, generation uint32) (time.Time, error) {
	w, stop, fence, err := q.leaseContext(ctx, intent, generation)
	if err != nil {
		return time.Time{}, err
	}
	defer stop()
	return q.store.Renew(w, fence)
}

func (q *workerQueue) releaseLease(ctx context.Context, intent delivery.IntentID, generation uint32) (delivery.CompleteResult, error) {
	w, stop, fence, err := q.leaseContext(ctx, intent, generation)
	if err != nil {
		return delivery.CompleteResult{}, err
	}
	defer stop()
	return q.store.Release(w, fence)
}
