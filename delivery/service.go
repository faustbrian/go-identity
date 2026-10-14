package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
)

// CommandID is the kernel's canonical command identity, not another journal.
type CommandID = identity.CommandID

// ErrNotFound is an enumeration-safe missing intent in the authorized scope.
var ErrNotFound = errors.New("delivery: not found")

// ErrForbidden rejects workflow, operator or authenticated provider binding.
var ErrForbidden = errors.New("delivery: forbidden")

// QueueBackend identifies explicit adapter selection, not a durability proof.
// Production composition must supply the owned PostgreSQL adapter, never an
// application-written store. A declaration does not authenticate a collaborator.
type QueueBackend uint8

const (
	QueueBackendPostgreSQL QueueBackend = iota + 1 // Owned durable PostgreSQL adapter.
	QueueBackendCapture                            // Explicit non-production capture.
)

// EnqueueRequest binds a versioned intent to its owning kernel command. The
// Scope is required for BoundQueue and forbidden for legacy capture admission.
// The owned adapter authorizes that exact command/tenant, obtains resource/expiry
// and provider configuration from its committed workflow binding, and enlists
// encrypted custody, dedupe and effects in the same transaction. NoOpEquivalent
// still requires a structurally valid message and the same public result shape.
// Callers must not mutate during a call; admission copies message slices.
type EnqueueRequest struct {
	TenantID       TenantID
	Message        Message
	IdempotencyKey string
	CommandID      CommandID
	NoOpEquivalent bool
	Scope          *EnqueueScope
	prepared       *RenderedMessage
}

// EnqueueScope carries the frozen owning workflow binding to an owned queue.
// It is trusted composition input, not authentication evidence. The adapter
// must authorize the binding and resolve the identifier before rendering.
// Callers must not mutate the scope during admission.
type EnqueueScope struct {
	Binding               identity.CommandBinding
	ActorScope            authorization.DecisionContext
	IdentifierID          identity.IdentifierID
	ProviderConfigVersion uint64
	ExpiresAt             time.Time
}

// Rendered returns the frozen core rendering for the owned queue's encryption
// boundary. False means service admission has not prepared this request. It is
// invocation-memory only; neither rendering nor this accessor grants authority.
func (r EnqueueRequest) Rendered() (RenderedMessage, bool) {
	if r.prepared == nil {
		return RenderedMessage{}, false
	}
	return *r.prepared, true
}

// Validate checks bounded shape, not command ownership or recipient existence.
func (r EnqueueRequest) Validate() error {
	message := r.Message
	if r.Scope != nil {
		if message.Recipient != (Recipient{}) || r.Scope.Binding.CommandID != r.CommandID || r.Scope.Binding.TenantID != identity.TenantID(r.TenantID) {
			return ErrInvalidInput
		}
		// Shape-only placeholder: never render or pass it to the adapter. Its
		// primary directory supplies the actual recipient after current policy.
		message.Recipient = Recipient{Channel: message.Channel, Address: "shape", ScopeDigest: strings.Repeat("0", 64)}
	}
	if !printableASCII(string(r.TenantID), 1, 128) || message.Validate() != nil || !printableASCII(r.IdempotencyKey, 16, 128) {
		return ErrInvalidInput
	}
	if _, err := identity.ParseCommandID(string(r.CommandID)); err != nil {
		return ErrInvalidInput
	}
	return nil
}

// EnqueueResult is local admission only. IntentID stays stable across matching
// duplicates; unknown/in-progress never authorize a new command or second send.
// NoOpEquivalent is internal workflow information, not a public existence bit.
type EnqueueResult struct {
	IntentID       IntentID
	Queued         bool
	NoOpEquivalent bool
	State          CommitState
}

// AdmissionUnknownError retains the original command even before an intent ID
// is known. Recover that command through the owning coordinator; do not reissue.
type AdmissionUnknownError struct {
	CommandID CommandID
	IntentID  IntentID
}

func (AdmissionUnknownError) Error() string { return "delivery: admission outcome unknown" }
func (AdmissionUnknownError) Unwrap() error { return ErrOutcomeUnknown }

// StatusGetRequest selects one exact authorized tenant/intent, not a lookup oracle.
type StatusGetRequest struct {
	TenantID TenantID
	IntentID IntentID
	Scope    *StatusScope
}

// StatusGetResult contains only redacted durable state; it reveals no payload.
// StatusVersion is the atomic primary fence for BoundQueue mutations. Zero is
// permitted only for legacy non-bound adapters; it cannot authorize a mutation.
type StatusGetResult struct {
	StatusVersion            uint64
	State                    DeliveryState
	AttemptGeneration        uint32
	Terminal                 bool
	ProviderReferencePresent bool
}

// CancelRequest fences unsent/retry work. Generation zero is permitted only for
// an authoritative never-attempted queued intent; all later generations match
// exactly. Reason is bounded operator metadata, never credentials or PII.
type CancelRequest struct {
	TenantID           TenantID
	IntentID           IntentID
	ExpectedGeneration uint32
	Reason             string
	Scope              *MutationScope
}

// CancelResult separates local prevention from authenticated remote evidence.
type CancelResult struct {
	State                       DeliveryState
	LocalCancelled              bool
	RemoteCancellationConfirmed bool
}

// ReceiptRecordRequest is normalized provider evidence. Fields and a provider
// name alone do not authenticate it; the owned adapter requires authenticated
// callback composition, exact effect/provider binding and durable event dedupe.
type ReceiptRecordRequest struct {
	TenantID        TenantID
	Provider        string
	ProviderEventID string
	IntentID        IntentID
	Generation      uint32
	Status          DeliveryState
	ObservedAt      time.Time
	IdempotencyKey  string
	Scope           *MutationScope
	Callback        *SignedReceiptCallback
}

// ReceiptRecordResult reports monotonic durable application, not raw receipts.
type ReceiptRecordResult struct {
	Deduplicated bool
	Advanced     bool
	State        DeliveryState
}

// ReconcileRequest binds a bounded provider query to an exact effect generation.
// The queue must query outside transactions, then checkpoint under generation CAS.
// Empty Checkpoint starts a lookup sequence; it does not reset durable progress
// or grant authority to replay an older generation or resubmit the delivery.
type ReconcileRequest struct {
	TenantID       TenantID
	IntentID       IntentID
	Generation     uint32
	Checkpoint     string
	IdempotencyKey string
	Scope          *ReconcileScope
}

// ReconcileResult never itself permits resubmission: pinned provider idempotency
// and current queue authority must separately admit any future attempt.
type ReconcileResult struct {
	State      DeliveryState
	Retryable  bool
	Checkpoint string
}

// Queue is the trusted owned adapter seam, not a consumer-provided domain store.
// All calls honor their bounded context. Mutations enforce authorization, audit,
// exact scope, durable dedupe and ambiguous-commit recovery. Enqueue accepts only
// service-prepared rendering in legacy mode; BoundQueue instead resolves and
// renders after authorization. It persists authenticated ciphertext, never these
// plaintext values. Claim returns after committing its lease and closing the
// transaction; no queue transaction spans Send or a provider query.
type Queue interface {
	Backend() QueueBackend
	Enqueue(context.Context, EnqueueRequest) (EnqueueResult, error)
	StatusGet(context.Context, StatusGetRequest) (StatusGetResult, error)
	Cancel(context.Context, CancelRequest) (CancelResult, error)
	ReceiptRecord(context.Context, ReceiptRecordRequest) (ReceiptRecordResult, error)
	Reconcile(context.Context, ReconcileRequest) (ReconcileResult, error)
	Claim(context.Context, ClaimRequest) (ClaimResult, error)
	Complete(context.Context, CompleteRequest) (CompleteResult, error)
}

// BoundQueue selects command-bound admission with adapter-owned authorization,
// recipient resolution and rendering. ValidateComposition must reject worker
// settings that disagree with the adapter's retained policy before any IO.
// Implementations remain trusted owned adapters, not consumer domain stores.
type BoundQueue interface {
	Queue
	ValidateComposition(Config) error
}

// ProcessResult preserves the stable intent and durable completion observation.
// Claimed=false means no attempt was returned, not that the queue is empty forever.
type ProcessResult = processResult

// Service owns bounded admission and one-attempt worker orchestration. It is
// safe for concurrent calls when its owned queue/renderer/sender are. It starts
// no goroutines, timers requiring shutdown or hidden retry loop. Call ProcessOne
// explicitly; cancellation and a caller's scheduling policy own worker lifetime.
type Service interface {
	Enqueue(context.Context, EnqueueRequest) (EnqueueResult, error)
	StatusGet(context.Context, StatusGetRequest) (StatusGetResult, error)
	Cancel(context.Context, CancelRequest) (CancelResult, error)
	ReceiptRecord(context.Context, ReceiptRecordRequest) (ReceiptRecordResult, error)
	Reconcile(context.Context, ReconcileRequest) (ReconcileResult, error)
	ProcessOne(context.Context, ClaimRequest) (ProcessResult, error)
}

type service struct {
	queue     Queue
	renderer  Renderer
	processor *attemptProcessor
	timeout   time.Duration
	bound     bool
}

func nilCollaborator(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return r.IsNil()
	}
	return false
}

// New selects explicit composition; there are no defaults or memory-durability
// fallback. Production rejects capture/missing Sender and undeclared durable
// queue profiles. BoundQueue owns rendering and permits nil Renderer; legacy
// queues require an explicit Renderer. Collaborators are trusted owners; profile
// declaration is configuration validation, not proof of live database safety.
func New(c Config, q Queue, r Renderer, s Sender) (Service, error) {
	if c.Validate() != nil || nilCollaborator(q) || c.Production && q.Backend() != QueueBackendPostgreSQL {
		return nil, ErrInvalidInput
	}
	_, bound := q.(BoundQueue)
	if bound {
		if err := q.(BoundQueue).ValidateComposition(c); err != nil {
			return nil, err
		}
	} else if nilCollaborator(r) {
		return nil, ErrInvalidInput
	}
	p, err := newAttemptProcessor(c, q, s)
	if err != nil {
		return nil, err
	}
	return &service{queue: q, renderer: r, processor: p, timeout: c.SenderTimeout, bound: bound}, nil
}

func (s *service) callContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	w, stop := context.WithTimeout(ctx, s.timeout)
	return w, stop, nil
}

// Enqueue renders exactly once before invoking a legacy queue. BoundQueue owns
// rendering after its authorization and recipient lookup; Sender is never called.
// After adapter invocation, unexplained failure is unknown rather than rollback.
func (s *service) Enqueue(ctx context.Context, r EnqueueRequest) (EnqueueResult, error) {
	if s.bound != (r.Scope != nil) || r.Validate() != nil {
		return EnqueueResult{}, ErrInvalidInput
	}
	w, stop, err := s.callContext(ctx)
	if err != nil {
		return EnqueueResult{}, err
	}
	defer stop()
	r.Message.LocaleChain = slices.Clone(r.Message.LocaleChain)
	r.Message.Variables = slices.Clone(r.Message.Variables)
	r.prepared = nil
	if r.Scope != nil {
		scope := *r.Scope
		r.Scope = &scope
	}
	if !s.bound {
		content, err := s.renderer.Render(w, r.Message)
		if err != nil {
			if w.Err() != nil {
				return EnqueueResult{}, w.Err()
			}
			return EnqueueResult{}, ErrInvalidInput
		}
		if !validRendered(content, r.Message.Channel) {
			return EnqueueResult{}, ErrInvalidInput
		}
		if err := w.Err(); err != nil {
			return EnqueueResult{}, err
		}
		r.prepared = &content
	}
	result, err := s.queue.Enqueue(w, r)
	if err != nil {
		for _, class := range []error{ErrInvalidInput, ErrForbidden, ErrConflict} {
			if errors.Is(err, class) {
				return EnqueueResult{}, class
			}
		}
		if s.bound {
			if errors.Is(err, ErrExpired) && result.State == CommitNotCommitted && !result.Queued {
				result.IntentID = safeIntent(result.IntentID)
				return result, ErrExpired
			}
			var original AdmissionUnknownError
			if errors.As(err, &original) {
				return EnqueueResult{IntentID: safeIntent(original.IntentID), State: CommitUnknown}, original
			}
			// A durable keyed admission may resolve a different original command.
			// Without that observation the submitted command is not recovery proof.
			return EnqueueResult{IntentID: safeIntent(result.IntentID), State: CommitUnknown}, ErrOutcomeUnknown
		}
		return EnqueueResult{IntentID: safeIntent(result.IntentID), State: CommitUnknown}, AdmissionUnknownError{CommandID: r.CommandID, IntentID: safeIntent(result.IntentID)}
	}
	if !validEnqueueResult(result, r) {
		if s.bound {
			return EnqueueResult{IntentID: safeIntent(result.IntentID), State: CommitUnknown}, ErrOutcomeUnknown
		}
		return EnqueueResult{IntentID: safeIntent(result.IntentID), State: CommitUnknown}, AdmissionUnknownError{CommandID: r.CommandID, IntentID: safeIntent(result.IntentID)}
	}
	if result.State == CommitUnknown || result.State == CommitInProgress {
		if s.bound {
			return result, ErrOutcomeUnknown
		}
		return result, AdmissionUnknownError{CommandID: r.CommandID, IntentID: result.IntentID}
	}
	if result.State == CommitConflict {
		return result, ErrConflict
	}
	return result, nil
}

func safeIntent(id IntentID) IntentID {
	if printableASCII(string(id), 16, 128) {
		return id
	}
	return ""
}
func validEnqueueResult(r EnqueueResult, request EnqueueRequest) bool {
	if r.State < CommitNotCommitted || r.State > CommitInProgress || r.NoOpEquivalent != request.NoOpEquivalent {
		return false
	}
	if r.State == CommitCommitted {
		return safeIntent(r.IntentID) != "" && r.Queued
	}
	return !r.Queued && (r.IntentID == "" || safeIntent(r.IntentID) != "")
}
func validRendered(r RenderedMessage, channel Channel) bool {
	a := Attempt{TenantID: "shape", IntentID: "synthetic-shape-id", Generation: 1, Channel: r.Channel, Recipient: "shape", Subject: r.Subject, Body: r.Body, ContentType: r.ContentType, IdempotencyKey: "synthetic-shape-id", ValidUntil: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}
	return r.Channel == channel && localeShape(r.Locale) && a.Validate() == nil
}
func validTarget(tenant TenantID, intent IntentID) bool {
	return printableASCII(string(tenant), 1, 128) && safeIntent(intent) != ""
}
func durableState(state DeliveryState) bool { return state >= StateQueued && state <= StateSuperseded }
func terminalState(state DeliveryState) bool {
	switch state {
	case StateDelivered, StateRejected, StateBounced, StateCancelled, StateExpired, StateExhausted, StateSuperseded:
		return true
	}
	return false
}
func stableQueueError(err error, mutation bool) error {
	for _, class := range []error{ErrInvalidInput, ErrForbidden, ErrNotFound, ErrConflict, ErrOutcomeUnknown} {
		if errors.Is(err, class) {
			return class
		}
	}
	if mutation {
		return ErrOutcomeUnknown
	}
	return ErrUnavailable
}

func (s *service) StatusGet(ctx context.Context, r StatusGetRequest) (StatusGetResult, error) {
	if !validTarget(r.TenantID, r.IntentID) || s.bound != (r.Scope != nil) {
		return StatusGetResult{}, ErrInvalidInput
	}
	w, stop, err := s.callContext(ctx)
	if err != nil {
		return StatusGetResult{}, err
	}
	defer stop()
	out, err := s.queue.StatusGet(w, r)
	if err != nil {
		return StatusGetResult{}, stableQueueError(err, false)
	}
	// Never-submitted intents may terminate without minting an attempt generation.
	needsAttempt := out.State != StateQueued && out.State != StateCancelled && out.State != StateExpired && out.State != StateSuperseded
	if !durableState(out.State) || out.Terminal != terminalState(out.State) || needsAttempt && out.AttemptGeneration == 0 || s.bound && out.StatusVersion == 0 {
		return StatusGetResult{}, ErrUnavailable
	}
	return out, nil
}
func (s *service) Cancel(ctx context.Context, r CancelRequest) (CancelResult, error) {
	if !validTarget(r.TenantID, r.IntentID) || !boundedText(r.Reason, 1, 256) || s.bound != (r.Scope != nil) {
		return CancelResult{}, ErrInvalidInput
	}
	w, stop, err := s.callContext(ctx)
	if err != nil {
		return CancelResult{}, err
	}
	defer stop()
	out, err := s.queue.Cancel(w, r)
	if err != nil {
		return CancelResult{}, stableQueueError(err, true)
	}
	// Preventing future local leases does not settle a prior external invocation.
	if !durableState(out.State) || out.LocalCancelled && out.State != StateCancelled && out.State != StateOutcomeUnknown || out.RemoteCancellationConfirmed && out.State != StateCancelled {
		return CancelResult{}, ErrOutcomeUnknown
	}
	return out, nil
}
func (s *service) ReceiptRecord(ctx context.Context, r ReceiptRecordRequest) (ReceiptRecordResult, error) {
	if r.Validate() != nil || s.bound != (r.Scope != nil) || s.bound != (r.Callback != nil) {
		return ReceiptRecordResult{}, ErrInvalidInput
	}
	w, stop, err := s.callContext(ctx)
	if err != nil {
		return ReceiptRecordResult{}, err
	}
	defer stop()
	out, err := s.queue.ReceiptRecord(w, r)
	if err != nil {
		return ReceiptRecordResult{}, stableQueueError(err, true)
	}
	if !durableState(out.State) || out.Advanced && out.Deduplicated {
		return ReceiptRecordResult{}, ErrOutcomeUnknown
	}
	return out, nil
}
func (s *service) Reconcile(ctx context.Context, r ReconcileRequest) (ReconcileResult, error) {
	if !validTarget(r.TenantID, r.IntentID) || r.Generation == 0 || r.Checkpoint != "" && !printableASCII(r.Checkpoint, 1, 512) || !printableASCII(r.IdempotencyKey, 16, 128) || s.bound != (r.Scope != nil) {
		return ReconcileResult{}, ErrInvalidInput
	}
	w, stop, err := s.callContext(ctx)
	if err != nil {
		return ReconcileResult{}, err
	}
	defer stop()
	out, err := s.queue.Reconcile(w, r)
	if err != nil {
		return ReconcileResult{}, stableQueueError(err, true)
	}
	if !durableState(out.State) || out.Checkpoint != "" && !printableASCII(out.Checkpoint, 1, 512) || out.Retryable && out.State != StateRetryWait {
		return ReconcileResult{}, ErrOutcomeUnknown
	}
	return out, nil
}
func (s *service) ProcessOne(ctx context.Context, r ClaimRequest) (ProcessResult, error) {
	return s.processor.processOne(ctx, r)
}

// Format and LogValue suppress complete admission and recovery diagnostics.
func (EnqueueRequest) Format(s fmt.State, _ rune)        { redact(s) }
func (AdmissionUnknownError) Format(s fmt.State, _ rune) { redact(s) }
func (EnqueueRequest) LogValue() slog.Value              { return slog.StringValue("delivery(redacted)") }
func (AdmissionUnknownError) LogValue() slog.Value       { return slog.StringValue("delivery(redacted)") }

// MarshalJSON/MarshalText refuse implicit plaintext queue persistence.
func (EnqueueRequest) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (EnqueueRequest) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }
