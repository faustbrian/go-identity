package delivery

import "context"

// WorkerQueue is the durable worker subset shared with Queue. Collaborators
// must be owned adapters: Backend is a selection declaration, not authentication
// or durability proof. Claim commits before returning plaintext; Complete owns
// generation-fenced bookkeeping. Neither method may span a provider callback.
type WorkerQueue interface {
	Backend() QueueBackend
	Claim(context.Context, ClaimRequest) (ClaimResult, error)
	Complete(context.Context, CompleteRequest) (CompleteResult, error)
}

// Worker owns one bounded claim/send/complete execution and its shared callback
// capacity. It starts no background work and is safe for concurrent calls when
// its queue and Sender are. The caller owns collaborators and scheduling.
// Construct once per retained provider/policy profile; do not recreate per call
// to evade the concurrency ceiling. Zero is invalid.
type Worker struct{ processor *attemptProcessor }

// NewWorker composes the same worker handshake used by Service without requiring
// unrelated admission operations. Production rejects missing/capture Sender and
// non-PostgreSQL selection. This does not turn an application queue into an owned
// durable adapter or grant authority from IDs. Config is copied by its owners.
func NewWorker(c Config, q WorkerQueue, sender Sender) (*Worker, error) {
	if c.Validate() != nil || nilCollaborator(q) || c.Production && q.Backend() != QueueBackendPostgreSQL {
		return nil, ErrInvalidInput
	}
	p, err := newAttemptProcessor(c, q, sender)
	if err != nil {
		return nil, err
	}
	return &Worker{processor: p}, nil
}

// ProcessOne leases at most one attempt, then invokes Sender after the queue
// returns. Capacity is acquired before Claim. Cancellation after invocation
// preserves attributable/unknown evidence under one additional synchronous
// bounded bookkeeping budget; ambiguity never authorizes automatic resend.
func (w *Worker) ProcessOne(ctx context.Context, request ClaimRequest) (ProcessResult, error) {
	if w == nil || w.processor == nil {
		return ProcessResult{}, ErrInvalidInput
	}
	return w.processor.processOne(ctx, request)
}
