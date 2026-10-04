package postgres

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	"github.com/faustbrian/go-identity/delivery"
)

// WorkerConfig selects one authenticated deployment worker and retained provider
// version. Scope is trusted composition input, not transport JSON: service-account
// subject, exact tenant, action identity.delivery.process, resource type
// identity.delivery-worker and resource ID equal to the worker name are required.
// PolicyRevision matches the admission service's current revision. The current
// authorization service reevaluates it for every lease and completion; IDs and
// previously allowed policy do not grant authority. Configuration is copied.
type WorkerConfig struct {
	Scope                 authorization.DecisionContext
	ProviderConfigVersion uint64
}

// Worker is the owned public PostgreSQL processing composition. It borrows the
// primary pool, envelope and authorization dependencies of EnqueueService and
// a bounded cooperative Sender. Construct once per worker/provider profile;
// concurrent ProcessOne calls share a capacity ceiling acquired before leasing.
// It owns no goroutines, retry loop, transport, pool lifetime or second journal.
// Zero is invalid. Full Queue admission composition remains separately owned.
type Worker struct {
	queue     *workerQueue
	processor *delivery.Worker
}

type workerQueue struct {
	store    *attemptStore
	service  *enqueueExecutor
	scope    authorization.DecisionContext
	request  delivery.ClaimRequest
	provider string
}

var _ delivery.WorkerQueue = (*workerQueue)(nil)

// NewWorker selects the exact retained provider's delivery policy, timeout,
// concurrency and retry limits, never the newest policy or a fallback. It does
// no IO and does not authenticate the supplied scope; every operation checks
// current policy before touching custody. Production rejects nil/capture Sender.
// Keep the worker alive to preserve its concurrency ceiling across calls.
func (s *EnqueueService) NewWorker(c WorkerConfig, sender delivery.Sender) (*Worker, error) {
	if s == nil || s.executor == nil || s.executor.custody == nil || s.policies == nil || c.ProviderConfigVersion == 0 || boundedDecisionContext(c.Scope) != nil {
		return nil, delivery.ErrInvalidInput
	}
	r := c.Scope.Request
	if r.Subject.Kind != authorization.SubjectServiceAccount || !safeID(string(r.Subject.ID), false) || !safeID(string(r.Tenant), false) || r.Action != "identity.delivery.process" || r.Resource.Type != "identity.delivery-worker" || !safeID(string(r.Resource.ID), false) || c.Scope.PolicyRevision != authorization.Revision(s.executor.policyVersion) || !safeID(c.Scope.CorrelationID, false) {
		return nil, delivery.ErrForbidden
	}
	for _, attrs := range []authorization.Attributes{r.Subject.Attributes, r.Resource.Attributes, r.Environment.Attributes, r.Attributes} {
		for name := range attrs {
			if strings.HasPrefix(string(name), "delivery.") {
				return nil, delivery.ErrInvalidInput
			}
		}
	}
	profile, ok := s.executor.custody.store.profiles[c.ProviderConfigVersion]
	if !ok {
		return nil, delivery.ErrUnavailable
	}
	store, err := s.policies.worker(profile.policyVersion, s.executor.custody.store.codec)
	if err != nil {
		return nil, err
	}
	store.providerVersion, store.receiptTracking = c.ProviderConfigVersion, s.receiptTracking
	q := &workerQueue{store: store, service: s.executor, scope: c.Scope.Clone(), request: delivery.ClaimRequest{TenantID: delivery.TenantID(r.Tenant), WorkerID: string(r.Resource.ID)}, provider: profile.name}
	processor, err := delivery.NewWorker(s.policies.profiles[profile.policyVersion], q, sender)
	if err != nil {
		return nil, err
	}
	return &Worker{queue: q, processor: processor}, nil
}

func (*workerQueue) Backend() delivery.QueueBackend { return delivery.QueueBackendPostgreSQL }

func (q *workerQueue) allow(ctx context.Context) (err error) {
	if ctx == nil || q == nil || q.service == nil || q.store == nil {
		return delivery.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	defer func() {
		if recover() != nil {
			err = delivery.ErrUnavailable
		}
	}()
	dc := q.scope.Clone()
	if dc.Request.Resource.Attributes == nil {
		dc.Request.Resource.Attributes = make(authorization.Attributes, 2)
	}
	dc.Request.Resource.Attributes["delivery.provider"] = authorization.StringValue(q.provider)
	dc.Request.Resource.Attributes["delivery.provider-config-version"] = authorization.StringValue(strconv.FormatUint(q.store.providerVersion, 10))
	dc.Request.Environment.Time = time.Now().UTC()
	decision, err := q.service.authorize.Decide(ctx, dc)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return delivery.ErrUnavailable
	}
	if decision.Outcome != authorization.Allow || decision.Revision != dc.PolicyRevision {
		return delivery.ErrForbidden
	}
	return nil
}

func (q *workerQueue) Claim(ctx context.Context, r delivery.ClaimRequest) (delivery.ClaimResult, error) {
	if q == nil || r != q.request {
		return delivery.ClaimResult{}, delivery.ErrForbidden
	}
	w, stop, err := q.store.bounded(ctx)
	if err != nil {
		return delivery.ClaimResult{}, err
	}
	defer stop()
	if err := q.allow(w); err != nil {
		return delivery.ClaimResult{}, err
	}
	claim, err := q.store.Claim(w, r)
	if err != nil || !claim.Claimed {
		return claim, err
	}
	// Policy may change while the committed lease is decrypted. Denial must
	// prevent Sender; owned no-invocation cleanup does not claim provider failure.
	if err := q.allow(w); err != nil {
		cleanup, finish := context.WithTimeout(context.WithoutCancel(ctx), q.store.maximumDuration)
		defer finish()
		_, _ = q.store.Complete(cleanup, delivery.CompleteRequest{TenantID: r.TenantID, WorkerID: r.WorkerID, IntentID: claim.Attempt.IntentID, Generation: claim.Attempt.Generation})
		return delivery.ClaimResult{}, err
	}
	return claim, nil
}

func (q *workerQueue) Complete(ctx context.Context, r delivery.CompleteRequest) (delivery.CompleteResult, error) {
	if q == nil || r.TenantID != q.request.TenantID || r.WorkerID != q.request.WorkerID {
		return delivery.CompleteResult{}, delivery.ErrForbidden
	}
	w, stop, err := q.store.bounded(ctx)
	if err != nil {
		return delivery.CompleteResult{}, err
	}
	defer stop()
	if err := q.allow(w); err != nil {
		return delivery.CompleteResult{}, err
	}
	return q.store.Complete(w, r)
}

// ProcessOne processes only this configured tenant/worker/provider. Provider IO
// follows a committed lease and current policy check outside SQL ownership.
// Unknown sends are checkpointed and never automatically retried. The caller
// schedules future calls and must retain the original intent for reconciliation.
func (w *Worker) ProcessOne(ctx context.Context) (delivery.ProcessResult, error) {
	if w == nil || w.processor == nil || w.queue == nil {
		return delivery.ProcessResult{}, delivery.ErrInvalidInput
	}
	return w.processor.ProcessOne(ctx, w.queue.request)
}

// Claim supports explicitly scheduled direct workers with the same current
// authority and committed provider/profile fence as ProcessOne. Plaintext is
// invocation memory only. Call Complete for this exact worker and generation;
// do not invoke Sender after lease expiry or turn uncertainty into a retry.
func (w *Worker) Claim(ctx context.Context) (delivery.ClaimResult, error) {
	if w == nil || w.queue == nil {
		return delivery.ClaimResult{}, delivery.ErrInvalidInput
	}
	return w.queue.Claim(ctx, w.queue.request)
}

// Complete checkpoints attributable evidence for an exact committed lease.
// Replays use the original worker/intent/generation/evidence; stale or changed
// evidence conflicts. Current denial or uncertain acknowledgement is not proof
// the provider failed. This method never invokes or resubmits a delivery.
func (w *Worker) Complete(ctx context.Context, r delivery.CompleteRequest) (delivery.CompleteResult, error) {
	if w == nil || w.queue == nil {
		return delivery.CompleteResult{}, delivery.ErrInvalidInput
	}
	return w.queue.Complete(ctx, r)
}

func (WorkerConfig) Format(s fmt.State, _ rune) { redactWorker(s) }
func (WorkerConfig) LogValue() slog.Value {
	return slog.StringValue("delivery.postgres.Worker(redacted)")
}
func (WorkerConfig) MarshalJSON() ([]byte, error) { return nil, delivery.ErrSerializationForbidden }
func (Worker) Format(s fmt.State, _ rune)         { redactWorker(s) }
func (Worker) LogValue() slog.Value               { return slog.StringValue("delivery.postgres.Worker(redacted)") }
func (Worker) MarshalJSON() ([]byte, error)       { return nil, delivery.ErrSerializationForbidden }
func redactWorker(s fmt.State)                    { _, _ = s.Write([]byte("delivery.postgres.Worker(redacted)")) }
