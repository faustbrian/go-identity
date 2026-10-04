package delivery

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"time"
)

// ErrConflict rejects a stale generation or conflicting durable checkpoint.
// It contains no recipient, provider evidence or raw queue diagnostics.
var ErrConflict = errors.New("delivery: conflict")

// ErrUnavailable means bounded queue/provider work could not be completed.
// It does not establish rejection, commit failure or permission to resubmit.
var ErrUnavailable = errors.New("delivery: unavailable")

// CompletionSnapshot is the owned adapter's current database-time view of one
// recorded attempt. State must be Attempting; both generations must be positive
// and equal, and AttemptNumber counts the already-recorded attempt (1..Attempts).
// Now/ValidUntil must be nonzero UTC values in years1..9999. Cancellation and
// expiry alone cannot establish the outcome of a potentially invoked provider.
// These exported fields convey shape, never authorization, a lease or CAS proof.
type CompletionSnapshot struct {
	State                          DeliveryState
	Generation, ExpectedGeneration uint32
	AttemptNumber                  uint8
	CancelRequested                bool
	Now, ValidUntil                time.Time
}

// CompletionDecision contains the queue policy's proposed state, retry instant
// (only for RetryWait) and required ciphertext erasure. Apply all components
// atomically under the exact tenant/intent/worker/generation CAS. Expiry may
// require erasure while State remains OutcomeUnknown; neither bit establishes
// an external effect. An adapter must not retain plaintext or turn a decision
// into permission to resubmit an outcome-unknown effect.
type CompletionDecision struct {
	State         DeliveryState
	NextAttemptAt time.Time
	ErasePayload  bool
}

// CompletionPolicy freezes validated delivery retry policy for owned adapters.
// It is safe for concurrent reads and never owns a store, workflow, transaction,
// clock, provider call or queue authority. Zero is invalid.
type CompletionPolicy struct{ config Config }

// NewCompletionPolicy validates and copies the caller-owned backoff slice.
// The caller must not mutate Config concurrently with construction; subsequent
// mutations do not affect this policy. There are no inferred defaults.
func NewCompletionPolicy(c Config) (CompletionPolicy, error) {
	if c.Validate() != nil {
		return CompletionPolicy{}, ErrInvalidInput
	}
	c.BackoffCeilings = append([]time.Duration(nil), c.BackoffCeilings...)
	return CompletionPolicy{config: c}, nil
}

// Decide reuses the core's exact completion rules with local cryptographic
// full jitter. Cancellation is checked before and after bounded policy work;
// nil context is invalid and cancelled calls return no usable decision.
// Snapshot must come from an authoritative adapter read, not cached freshness.
// The adapter owns time/precision conversion and must preserve expiry and retry
// bounds when applying the returned instant in its atomic generation-CAS.
func (p CompletionPolicy) Decide(ctx context.Context, current CompletionSnapshot, evidence DeliveryResult) (CompletionDecision, error) {
	if ctx == nil {
		return CompletionDecision{}, ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return CompletionDecision{}, err
	}
	decision, err := planCompletion(p.config, current, evidence, rand.Reader)
	if cancelled := ctx.Err(); cancelled != nil {
		return CompletionDecision{}, cancelled
	}
	return decision, err
}

// Internal names retain the same implementation and focused entropy tests.
type completionInput = CompletionSnapshot
type completionPlan = CompletionDecision

// planCompletion decides only a just-finished, recorded attempt. Authenticated
// receipts/reconciliation have separate monotonic admission; in particular an
// unknown attempt is never eligible here for automatic resubmission.
func planCompletion(c Config, in completionInput, result DeliveryResult, entropy io.Reader) (completionPlan, error) {
	if c.Validate() != nil || in.State != StateAttempting || in.Generation == 0 || in.ExpectedGeneration == 0 || in.AttemptNumber == 0 || in.AttemptNumber > c.Attempts || !validUTCTime(in.Now) || !validUTCTime(in.ValidUntil) || result.Validate() != nil {
		return completionPlan{}, ErrInvalidInput
	}
	if in.Generation != in.ExpectedGeneration {
		return completionPlan{}, ErrConflict
	}
	expired := !in.ValidUntil.After(in.Now)
	if result.State != StateTransientFailure {
		terminal := result.State == StateDelivered || result.State == StateRejected || result.State == StateBounced
		// Expiry erases bearer custody even when provider outcome is unknown;
		// it is not evidence that the external effect failed or was cancelled.
		return completionPlan{State: result.State, ErasePayload: terminal || expired}, nil
	}
	stop := func(state DeliveryState) (completionPlan, error) {
		return completionPlan{State: state, ErasePayload: true}, nil
	}
	// Only authoritative no-success evidence allows these local terminal
	// outcomes. Cancellation never converts actual acceptance to cancellation.
	if in.CancelRequested {
		return stop(StateCancelled)
	}
	if expired {
		return stop(StateExpired)
	}
	if in.AttemptNumber == c.Attempts {
		return stop(StateExhausted)
	}
	if entropy == nil {
		return completionPlan{}, ErrUnavailable
	}
	ceiling := c.BackoffCeilings[in.AttemptNumber]
	// Inclusive nanosecond full jitter. Cap rejection-sampling input so even a
	// broken injected entropy source cannot cause unbounded policy work.
	draw, err := rand.Int(io.LimitReader(progressEntropy{entropy}, 256), big.NewInt(int64(ceiling)+1))
	if err != nil {
		return completionPlan{}, ErrUnavailable
	}
	delay := max(time.Duration(draw.Int64()), result.RetryAfter)
	next := in.Now.Add(delay)
	if !next.Before(in.ValidUntil) {
		return stop(StateExpired)
	}
	return completionPlan{State: StateRetryWait, NextAttemptAt: next}, nil
}

// A byte budget alone does not bound io.ReadFull: a Reader may legally return
// (0,nil). Reject that result so every successful read consumes the byte budget.
// Entropy sources are trusted local dependencies and must not block forever.
type progressEntropy struct{ reader io.Reader }

func (r progressEntropy) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if n < 0 || n > len(p) || n == 0 && err == nil {
		return 0, io.ErrNoProgress
	}
	return n, err
}
