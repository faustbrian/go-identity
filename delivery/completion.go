package delivery

import (
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

// These are internal queue-policy values, not a second authority or store.
// The durable adapter must supply database-time snapshots under a generation
// CAS and apply state, schedule and ciphertext erasure in one transaction.
type completionInput struct {
	State                          DeliveryState
	Generation, ExpectedGeneration uint32
	AttemptNumber                  uint8
	CancelRequested                bool
	Now, ValidUntil                time.Time
}

type completionPlan struct {
	State         DeliveryState
	NextAttemptAt time.Time
	ErasePayload  bool
}

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
