package delivery

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// OutcomeQuery binds a provider read to the original persisted submission
// identity and exact effect generation. ProviderIdempotencyKey is the original
// provider key, never the reconciliation command's key. Checkpoint is a bounded
// opaque provider cursor; empty begins a new lookup sequence. Neither field grants tenant authority or retry
// permission; the owned adapter authenticates and supplies this snapshot.
// No recipient or rendered payload is needed for a status query.
type OutcomeQuery struct {
	TenantID               TenantID
	IntentID               IntentID
	Generation             uint32
	ProviderIdempotencyKey string
	Checkpoint             string
}

// Validate proves shape only, not ownership, a provider profile or a CAS fence.
func (q OutcomeQuery) Validate() error {
	if !validTarget(q.TenantID, q.IntentID) || q.Generation == 0 || !printableASCII(q.ProviderIdempotencyKey, 16, 128) || q.Checkpoint != "" && !printableASCII(q.Checkpoint, 1, 512) {
		return ErrInvalidInput
	}
	return nil
}

// OutcomeObservation is normalized attributable provider evidence. Checkpoint
// is the next cursor (empty ends a query sequence), never durable admission.
// RetryAfter is a 0..2m hint for TransientFailure only. An unknown observation
// is valid evidence of uncertainty, not permission to retry. The adapter owns
// monotonic ordering, timestamp precision, persistence and generation CAS.
type OutcomeObservation struct {
	State      DeliveryState
	ObservedAt time.Time
	RetryAfter time.Duration
	Checkpoint string
}

// Validate rejects local queue states, invalid UTC times and unbounded cursors.
// Cancelled is allowed only as attributable provider cancellation evidence;
// the adapter must also enforce the current cancellation-pending transition.
func (o OutcomeObservation) Validate() error {
	switch o.State {
	case StateAccepted, StateDelivered, StateRejected, StateBounced, StateCancelled, StateOutcomeUnknown, StateTransientFailure:
	default:
		return ErrInvalidInput
	}
	if !validUTCTime(o.ObservedAt) || o.RetryAfter < 0 || o.RetryAfter > 2*time.Minute || o.State != StateTransientFailure && o.RetryAfter != 0 || o.Checkpoint != "" && !printableASCII(o.Checkpoint, 1, 512) {
		return ErrInvalidInput
	}
	return nil
}

// OutcomeQuerier is an optional bounded provider status seam, separate from
// Sender. It must authenticate the provider response, honor cancellation,
// never submit/cancel/retry a delivery, and not retain query inputs. Provider
// support for lookup by the original idempotency identity must be explicitly
// pinned by the owned adapter; unsupported lookup must return an error.
// A query runs outside database transactions, locks and kernel reservations.
type OutcomeQuerier interface {
	QueryOutcome(context.Context, OutcomeQuery) (OutcomeObservation, error)
}

// OutcomeQueryExecutor owns synchronous deadline and concurrency enforcement,
// not a store, workflow or provider contract. Zero is invalid; use the
// constructor and retain its pointer (do not copy it). Concurrent calls are
// safe when the borrowed querier is. The querier must cooperate with deadlines:
// Go cannot safely stop arbitrary callback code. No goroutines or retries are
// started, and queue expiry does not prevent reconciliation of an old effect.
type OutcomeQueryExecutor struct {
	querier OutcomeQuerier
	timeout time.Duration
	slots   chan struct{}
}

// NewOutcomeQueryExecutor requires timeout1..30s, concurrency1..64 and a non-nil
// borrowed callback. The caller retains callback ownership and shutdown. There
// is no IO or implicit production provider selection during construction.
func NewOutcomeQueryExecutor(timeout time.Duration, concurrency uint8, querier OutcomeQuerier) (*OutcomeQueryExecutor, error) {
	if timeout < time.Second || timeout > 30*time.Second || concurrency < 1 || concurrency > 64 || nilCollaborator(querier) {
		return nil, ErrInvalidInput
	}
	return &OutcomeQueryExecutor{querier: querier, timeout: timeout, slots: make(chan struct{}, int(concurrency))}, nil
}

// Query invokes once after bounded slot acquisition. Parent cancellation or
// deadline returns its context error and no evidence, including late callback
// success. Provider errors, panics and malformed responses become redacted
// ErrUnavailable with a zero result, never synthetic observed-at/checkpoint
// evidence. A valid OutcomeUnknown observation is returned unchanged. No
// result authorizes resubmission or bypasses the adapter's current policy/CAS.
func (e *OutcomeQueryExecutor) Query(ctx context.Context, q OutcomeQuery) (OutcomeObservation, error) {
	if ctx == nil || e == nil || e.querier == nil || e.slots == nil || q.Validate() != nil {
		return OutcomeObservation{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return OutcomeObservation{}, err
	}
	call, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	case <-call.Done():
		return OutcomeObservation{}, call.Err()
	}
	if err := call.Err(); err != nil {
		return OutcomeObservation{}, err
	}
	result, err := invokeOutcomeQuery(call, e.querier, q)
	if cancelled := call.Err(); cancelled != nil {
		return OutcomeObservation{}, cancelled
	}
	if err != nil || result.Validate() != nil {
		return OutcomeObservation{}, ErrUnavailable
	}
	return result, nil
}

func invokeOutcomeQuery(ctx context.Context, querier OutcomeQuerier, q OutcomeQuery) (result OutcomeObservation, err error) {
	defer func() {
		if recover() != nil {
			result, err = OutcomeObservation{}, ErrUnavailable
		}
	}()
	return querier.QueryOutcome(ctx, q)
}

// Format/LogValue redact query identities, keys and cursors for all verbs.
func (OutcomeQuery) Format(s fmt.State, _ rune)         { redact(s) }
func (OutcomeObservation) Format(s fmt.State, _ rune)   { redact(s) }
func (OutcomeQueryExecutor) Format(s fmt.State, _ rune) { redact(s) }
func (OutcomeQuery) LogValue() slog.Value               { return slog.StringValue("delivery(redacted)") }
func (OutcomeObservation) LogValue() slog.Value         { return slog.StringValue("delivery(redacted)") }
func (OutcomeQueryExecutor) LogValue() slog.Value       { return slog.StringValue("delivery(redacted)") }

// MarshalJSON/MarshalText refuse implicit persistence of provider keys/cursors.
func (OutcomeQuery) MarshalJSON() ([]byte, error)         { return nil, ErrSerializationForbidden }
func (OutcomeObservation) MarshalJSON() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (OutcomeQueryExecutor) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }
func (OutcomeQuery) MarshalText() ([]byte, error)         { return nil, ErrSerializationForbidden }
func (OutcomeObservation) MarshalText() ([]byte, error)   { return nil, ErrSerializationForbidden }
func (OutcomeQueryExecutor) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }
