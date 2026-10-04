package delivery

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"time"
)

// CommitState describes durable queue bookkeeping, not an external effect.
// Zero/unknown values are invalid; Committed never by itself means Delivered.
type CommitState uint8

const (
	CommitNotCommitted CommitState = iota + 1 // Authoritatively not committed.
	CommitCommitted                           // Durable queue transition committed.
	CommitUnknown                             // Recover; do not submit again.
	CommitConflict                            // Current generation rejected this writer.
	CommitInProgress                          // Durable command is still being resolved.
)

// ClaimRequest scopes one bounded worker claim. Tenant/worker IDs are exact
// 1..128 printable ASCII bytes; neither authenticates a worker or grants access.
// The owned adapter must authenticate composition and persist a live lease and
// attempt generation before returning ClaimResult. No database work spans Send.
type ClaimRequest struct {
	TenantID TenantID
	WorkerID string
}

// Validate checks structural scope only; queue authorization remains required.
func (r ClaimRequest) Validate() error {
	if !printableASCII(string(r.TenantID), 1, 128) || !printableASCII(r.WorkerID, 1, 128) {
		return ErrInvalidInput
	}
	return nil
}

// ClaimResult transfers one already-rendered attempt to the worker. Claimed=false
// requires every other field zero; Claimed=true requires an exact tenant-bound
// valid attempt and UTC lease expiry. Plaintext is invocation-memory only, never
// implicit serialization. Shape alone proves neither durability nor ownership.
type ClaimResult struct {
	Claimed    bool
	Attempt    Attempt
	LeaseUntil time.Time
}

// Validate binds a returned claim to the requested tenant. Actual live lease,
// generation, cancellation and current authority are enforced by the adapter.
func (r ClaimResult) Validate(request ClaimRequest) error {
	if request.Validate() != nil {
		return ErrInvalidInput
	}
	if !r.Claimed {
		if r.Attempt != (Attempt{}) || !r.LeaseUntil.IsZero() {
			return ErrInvalidInput
		}
		return nil
	}
	if r.Attempt.Validate() != nil || r.Attempt.TenantID != request.TenantID || !validUTCTime(r.LeaseUntil) {
		return ErrInvalidInput
	}
	return nil
}

// CompleteRequest binds post-callback evidence to the same tenant, intent,
// worker and positive generation. Invoked=false requires zero Result and proves
// only that this worker did not call Send; adapter CAS/current authority still
// decide whether any local transition is admissible. Invoked=true requires a
// normalized provider result, including OutcomeUnknown when ambiguous.
type CompleteRequest struct {
	TenantID   TenantID
	IntentID   IntentID
	WorkerID   string
	Generation uint32
	Invoked    bool
	Result     DeliveryResult
}

// Validate rejects unbound completion and contradictory invocation evidence.
func (r CompleteRequest) Validate() error {
	if (ClaimRequest{TenantID: r.TenantID, WorkerID: r.WorkerID}).Validate() != nil || !printableASCII(string(r.IntentID), 16, 128) || r.Generation == 0 {
		return ErrInvalidInput
	}
	if r.Invoked {
		return r.Result.Validate()
	}
	if r.Result != (DeliveryResult{}) {
		return ErrInvalidInput
	}
	return nil
}

// CompleteResult reports redacted durable state and command disposition.
// The adapter must generation-CAS state, schedule, erasure and replay authority
// together. Provider TransientFailure is never a durable queue state.
type CompleteResult struct {
	State  DeliveryState
	Commit CommitState
}

// Validate checks the closed state/disposition shape, not durable commit proof.
func (r CompleteResult) Validate() error {
	if r.State < StateQueued || r.State > StateSuperseded || r.Commit < CommitNotCommitted || r.Commit > CommitInProgress {
		return ErrInvalidInput
	}
	if r.Commit == CommitCommitted && r.State == StateAttempting {
		return ErrInvalidInput
	}
	return nil
}

// This is the consumer-owned worker subset of the eventual public Queue.
// It is not a store, workflow or application-provided orchestration engine.
type attemptQueue interface {
	Claim(context.Context, ClaimRequest) (ClaimResult, error)
	Complete(context.Context, CompleteRequest) (CompleteResult, error)
}

type attemptProcessor struct {
	queue  attemptQueue
	sender *senderExecutor
	slots  chan struct{}
}

type processResult struct {
	Claimed    bool
	IntentID   IntentID
	Completion CompleteResult
}

func newAttemptProcessor(c Config, q attemptQueue, s Sender) (*attemptProcessor, error) {
	if q == nil {
		return nil, ErrInvalidInput
	}
	v := reflect.ValueOf(q)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if v.IsNil() {
			return nil, ErrInvalidInput
		}
	}
	exec, err := newSenderExecutor(c, s)
	if err != nil {
		return nil, err
	}
	return &attemptProcessor{queue: q, sender: exec, slots: make(chan struct{}, int(c.SenderConcurrency))}, nil
}

// One synchronous bounded claim/send/complete; no retry loop or goroutine.
// Production service construction must select the named owned durable adapter;
// this private primitive alone makes no production-durability assertion.
func (p *attemptProcessor) processOne(ctx context.Context, request ClaimRequest) (processResult, error) {
	if ctx == nil || p == nil || p.queue == nil || p.sender == nil || p.slots == nil || request.Validate() != nil {
		return processResult{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return processResult{}, err
	}
	work, cancel := context.WithTimeout(ctx, p.sender.timeout)
	defer cancel()
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	case <-work.Done():
		return processResult{}, work.Err()
	}
	if err := work.Err(); err != nil {
		return processResult{}, err
	}
	claim, err := p.queue.Claim(work, request)
	if err != nil {
		for _, class := range []error{ErrOutcomeUnknown, ErrConflict, ErrInvalidInput} {
			if errors.Is(err, class) {
				return processResult{}, class
			}
		}
		return processResult{}, ErrUnavailable
	}
	if claim.Validate(request) != nil {
		return processResult{}, ErrInvalidInput
	}
	if !claim.Claimed {
		return processResult{}, nil
	}
	out := processResult{Claimed: true, IntentID: claim.Attempt.IntentID}
	call, stop := context.WithDeadline(work, claim.LeaseUntil)
	result, sendErr := p.sender.send(call, claim.Attempt)
	stop()
	// senderExecutor returns a nonzero normalized result exactly when the
	// callback ran; cancellation/expiry before invocation returns zero result.
	completion := CompleteRequest{TenantID: request.TenantID, IntentID: claim.Attempt.IntentID, WorkerID: request.WorkerID, Generation: claim.Attempt.Generation, Invoked: result.State != 0, Result: result}
	// Preserve attributable/ambiguous evidence after caller cancellation, but
	// only synchronously within one bounded bookkeeping budget. This is not a
	// detached retry and cannot renew authorization or the queue generation.
	bookkeeping, finish := context.WithTimeout(context.WithoutCancel(ctx), p.sender.timeout)
	defer finish()
	durable, completeErr := p.queue.Complete(bookkeeping, completion)
	if completeErr != nil || durable.Validate() != nil || durable.Commit != CommitCommitted {
		out.Completion = CompleteResult{State: StateOutcomeUnknown, Commit: CommitUnknown}
		if errors.Is(completeErr, ErrConflict) || completeErr == nil && durable.Validate() == nil && durable.Commit == CommitConflict {
			out.Completion.Commit = CommitConflict
			return out, errors.Join(ErrConflict, OutcomeUnknownError{IntentID: out.IntentID})
		}
		return out, OutcomeUnknownError{IntentID: out.IntentID}
	}
	out.Completion = durable
	if sendErr != nil {
		if !completion.Invoked {
			return out, sendErr
		}
		return out, OutcomeUnknownError{IntentID: out.IntentID}
	}
	return out, nil
}

// Format suppresses invocation content/provider evidence for every fmt verb.
func (ClaimResult) Format(s fmt.State, _ rune)     { redact(s) }
func (CompleteRequest) Format(s fmt.State, _ rune) { redact(s) }

// LogValue suppresses sensitive queue-transfer values in structured logs.
func (ClaimResult) LogValue() slog.Value     { return slog.StringValue("delivery(redacted)") }
func (CompleteRequest) LogValue() slog.Value { return slog.StringValue("delivery(redacted)") }

// MarshalJSON refuses implicit sensitive queue persistence.
func (ClaimResult) MarshalJSON() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (CompleteRequest) MarshalJSON() ([]byte, error) { return nil, ErrSerializationForbidden }

// MarshalText refuses implicit sensitive queue serialization.
func (ClaimResult) MarshalText() ([]byte, error)     { return nil, ErrSerializationForbidden }
func (CompleteRequest) MarshalText() ([]byte, error) { return nil, ErrSerializationForbidden }
